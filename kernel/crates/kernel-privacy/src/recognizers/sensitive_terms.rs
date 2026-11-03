//! Deterministic sensitive-terms recogniser (GDPR Art. 9 special categories).
//!
//! Health data is special-category data, so every health term must be masked
//! in full. The recogniser holds a closed, versioned lexicon of unambiguous
//! terms: diagnoses, conditions, treatments and medical-context words in FR,
//! EN, AF, HU, SL and ZH. The vocabulary lives in
//! `data/sensitive-terms-v1.tsv`, compiled into the binary with `include_str!`.
//! Each line is `CATEGORY <TAB> LANG <TAB> TERM`; matching ignores the language.
//!
//! ## Matching
//!
//! * A Latin term is a whole word. The text splits into maximal runs of letters
//!   and digits, and each run is folded to lowercase with its diacritics removed
//!   (NFKD, combining marks dropped), so `Chimiothérapie`, `chimiotherapie` and
//!   `CHIMIOTHÉRAPIE` are one word.
//! * A term fires on the word, and on its plural or feminine form (`s`, `es`,
//!   `e`). A trailing `*` marks a stem: `cukorbeteg*` matches every word that
//!   starts with it.
//! * An exception line (`term|list`) takes words away from a term: a Latin
//!   term lists the words it must not match (`FIV|five,fives`), a Han term the
//!   suffix that must not follow it (`中风|险`).
//! * A multi-word term (`sick leave`, `self-harm`) matches consecutive words
//!   separated only by whitespace, hyphens, apostrophes or invisible characters.
//! * A Han term matches as a substring, because a Chinese sentence has no
//!   spaces between its words.
//!
//! ## Precision
//!
//! Terms fire without a context anchor, so a health value cannot leak past a
//! missing pronoun. Some terms have a common meaning elsewhere, and they
//! over-mask by design: `cancer` as a zodiac sign, `enceinte` as a loudspeaker,
//! `aids` as teaching aids, `rak` as a crab. A name that is also a term is left
//! out of the lexicon.
//!
//! The recogniser never opens a socket, runs a model or logs a value.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::contacts::fold::{homoglyph, is_cyrillic, is_default_ignorable, is_greek};
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// The versioned lexicon, compiled into the binary.
const DATA: &str = include_str!("../../data/sensitive-terms-v1.tsv");
/// Multiword conditions gated on a personal sentence frame.
const PERSONAL_CONDITIONS: &str = include_str!("../../data/personal-health-conditions-v1.tsv");

/// Score of every lexicon hit. A hit is unambiguous, so it sits above every
/// kind floor and keeps its specific label.
pub const SCORE: f32 = 1.0;

/// The name echoed in [`Span::recognizer`].
const NAME: &str = "sensitive_terms";

/// Shortest one-word term, in folded bytes, that a glued tag may hide.
const MIN_TAGGED: usize = 8;
/// Longest ASCII tag glued before or after a term (`ref`, `ok`, `id42`).
const MAX_TAG: usize = 4;

/// Finds the Art. 9 terms of the lexicon.
#[derive(Clone, Copy, Debug, Default)]
pub struct SensitiveTermsRecognizer;

impl SensitiveTermsRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for SensitiveTermsRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[
            EntityKind::Health,
            EntityKind::Religion,
            EntityKind::SexualOrientation,
            EntityKind::Union,
            EntityKind::Ethnicity,
        ]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let lexicons = lexicons();
        let words = words(text);
        let mut hits: Vec<Hit> = Vec::new();
        let mut cues: Vec<Hit> = Vec::new();
        for index in 0..words.len() {
            lexicons.terms.match_at(text, &words, index, &mut hits);
            lexicons.cues.match_at(text, &words, index, &mut cues);
        }
        lexicons.terms.push_compounds(&words, &mut hits);
        lexicons.terms.push_tagged(&words, &mut hits);
        push_hu_rak(text, &words, &mut hits);
        push_disease_names(text, &words, &mut hits, false);
        push_eponym_possessives(text, &words, &mut hits);
        // Frame-only promotions must never become sentence-wide anchors.
        let mut frames = Vec::new();
        push_disease_names(text, &words, &mut frames, true);
        // Han terms match on the view of the text: traditional characters read
        // as simplified ones, and the matched spans map back to the original.
        if text.chars().any(is_han) {
            let view = HanView::new(text);
            push_han(
                &view,
                &lexicons.terms.han,
                &lexicons.terms.han_except,
                &mut hits,
            );
            push_han_disease_names(&view, text, &mut hits);
            push_han(
                &view,
                &lexicons.cues.han,
                &lexicons.cues.han_except,
                &mut cues,
            );
        }
        extend_quantified_health(text, &words, &mut hits);
        // An ambiguous abbreviation stands only when a strong term or a health
        // cue shares its sentence.
        let mut anchors: HashMap<&'static str, Vec<usize>> = HashMap::new();
        for hit in hits.iter().filter(|hit| !hit.contextual).chain(cues.iter()) {
            anchors.entry(hit.lang).or_default().push(hit.span.start);
        }
        for starts in anchors.values_mut() {
            starts.sort_unstable();
        }
        let mut spans: Vec<Span> = hits
            .into_iter()
            .filter(|hit| {
                if !hit.contextual {
                    return true;
                }
                let own = anchors.get(hit.lang).map_or(&[][..], Vec::as_slice);
                cued(text, hit.span, own) && !dated(text, hit.span)
            })
            .chain(frames)
            .map(|hit| hit.span)
            .collect();
        spans.extend(personal_condition_spans(text, &words));
        extend_condition_spans(text, &words, &mut spans);
        // Two entries can reach the same word (`cancer` and its plural rule):
        // one span per range and kind is enough.
        let mut seen = HashSet::new();
        spans.retain(|span| seen.insert((span.start, span.end, span.kind)));
        spans
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

/// Match multiword conditions only when a personal frame occurs in the same
/// sentence. The finite table keeps this scan linear in input length.
fn personal_condition_spans(text: &str, word_list: &[Word]) -> Vec<Span> {
    static TERMS: OnceLock<HashMap<String, Vec<Vec<String>>>> = OnceLock::new();
    static HAN_TERMS: OnceLock<Vec<String>> = OnceLock::new();
    let terms = TERMS.get_or_init(|| {
        let mut indexed: HashMap<String, Vec<Vec<String>>> = HashMap::new();
        for term in PERSONAL_CONDITIONS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .filter_map(|line| {
                let (lang, term) = line.split_once('\t')?;
                (lang != "zh").then_some(term)
            })
        {
            let tokens: Vec<String> = words(term).into_iter().map(|word| word.folded).collect();
            if let Some(first) = tokens.first() {
                indexed.entry(first.clone()).or_default().push(tokens);
            }
        }
        indexed
    });
    let han_terms = HAN_TERMS.get_or_init(|| {
        PERSONAL_CONDITIONS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .filter_map(|line| {
                let (lang, term) = line.split_once('\t')?;
                (lang == "zh").then(|| HanView::new(term).text)
            })
            .collect()
    });
    let mut personal_frames: Option<Vec<bool>> = None;
    let mut out = Vec::new();
    for (start, word) in word_list.iter().enumerate() {
        let Some(candidates) = terms.get(&word.folded) else {
            continue;
        };
        let frames = personal_frames.get_or_insert_with(|| personal_frame_flags(text, word_list));
        for term in candidates {
            let end = start + term.len();
            if end > word_list.len()
                || word_list[start..end]
                    .iter()
                    .zip(term)
                    .any(|(word, token)| &word.folded != token)
                || (start + 1..end).any(|at| {
                    !joins_condition_phrase(text, word_list[at - 1].end, word_list[at].start)
                })
            {
                continue;
            }
            if frames[start] {
                out.push(Span::new(
                    EntityKind::Health,
                    word_list[start].start,
                    word_list[end - 1].end,
                    SCORE,
                    NAME,
                ));
            }
        }
    }
    if !han_terms.is_empty() && text.chars().any(is_han) {
        let view = HanView::new(text);
        let personal_frames = personal_frame_byte_flags(text);
        for term in han_terms {
            for (from, matched) in view.text.match_indices(term) {
                if let Some((start, end)) = view.original(from, from + matched.len()) {
                    if personal_frames[start] {
                        out.push(Span::new(EntityKind::Health, start, end, SCORE, NAME));
                    }
                }
            }
        }
    }
    out
}

/// A lexicon phrase may cross a line only at a visible hyphen continuation.
fn joins_condition_phrase(text: &str, from: usize, to: usize) -> bool {
    let Some(gap) = text.get(from..to) else {
        return false;
    };
    joins(text, from, to)
        && (!gap.contains(['\n', '\r'])
            || gap
                .trim_end_matches(['\n', '\r', ' '])
                .ends_with(['-', '‐', '‑', '–', '\\']))
}

/// Mark each Latin word in a sentence once, so a hit never rescans a sentence.
fn personal_frame_flags(text: &str, words: &[Word]) -> Vec<bool> {
    const FRAME: &[&str] = &[
        "i", "me", "my", "mine", "we", "our", "he", "his", "she", "her", "they", "their", "je",
        "j", "jaz", "ma", "mon", "mes", "moi", "elle", "il", "nous", "hy", "sy", "ek", "ons",
        "haar", "hul", "nekem", "nalam", "я", "мой", "моя", "мое",
    ];
    let mut flags = vec![false; words.len()];
    let mut first = 0;
    for boundary in 1..=words.len() {
        let ends_sentence = boundary == words.len()
            || text[words[boundary - 1].end..words[boundary].start]
                .chars()
                .any(|ch| is_sentence_end(ch) || ch == '\n' || ch == '\r');
        if !ends_sentence {
            continue;
        }
        let has_frame = words[first..boundary]
            .iter()
            .any(|word| FRAME.contains(&word.folded.as_str()));
        flags[first..boundary].fill(has_frame);
        first = boundary;
    }
    flags
}

/// Mark original byte positions in personally framed sentences, including Han text.
fn personal_frame_byte_flags(text: &str) -> Vec<bool> {
    const FRAME: &[&str] = &[
        "i", "me", "my", "mine", "we", "our", "he", "his", "she", "her", "they", "their", "je",
        "j", "jaz", "ma", "mon", "mes", "moi", "elle", "il", "nous", "hy", "sy", "ek", "ons",
        "haar", "hul", "nekem", "nalam", "я", "мой", "моя", "мое", "我", "我们", "我的",
    ];
    let mut flags = vec![false; text.len() + 1];
    let mut start = 0;
    for (at, ch) in text.char_indices() {
        if !is_sentence_end(ch) && ch != '\r' {
            continue;
        }
        let end = at + ch.len_utf8();
        let sentence = &text[start..end];
        let folded = fold_str(sentence);
        let sentence_words: HashSet<String> = words(sentence)
            .into_iter()
            .map(|word| word.folded)
            .collect();
        let framed = FRAME.iter().any(|frame| {
            if frame.chars().any(is_han) {
                folded.contains(frame)
            } else {
                sentence_words.contains(&fold_str(frame))
            }
        });
        flags[start..end].fill(framed);
        start = end;
    }
    if start < text.len() {
        let sentence = &text[start..];
        let folded = fold_str(sentence);
        let sentence_words: HashSet<String> = words(sentence)
            .into_iter()
            .map(|word| word.folded)
            .collect();
        let framed = FRAME.iter().any(|frame| {
            if frame.chars().any(is_han) {
                folded.contains(frame)
            } else {
                sentence_words.contains(&fold_str(frame))
            }
        });
        flags[start..=text.len()].fill(framed);
    }
    flags
}

/// Extend a health span through adjacent condition modifiers, bounded to six
/// tokens / sixty bytes and one physical line.
fn extend_condition_spans(text: &str, words: &[Word], spans: &mut [Span]) {
    const MODIFIERS: &[&str] = &[
        "acute",
        "chronic",
        "mild",
        "moderate",
        "severe",
        "early",
        "onset",
        "late",
        "stage",
        "type",
        "left",
        "right",
        "bilateral",
        "unilateral",
        "post",
        "pre",
        "related",
        "gestational",
        "idiopathic",
        "juvenile",
        "focal",
        "viral",
        "infectious",
        "sided",
        "et",
        "en",
        "siekte",
        "tipe",
        "1",
        "2",
        "3",
        "4",
        "5",
        "i",
        "ii",
        "iii",
    ];
    const CONDITION_WORDS: &[&str] = &[
        "multiple",
        "polycystic",
        "ovary",
        "ulcerative",
        "traumatic",
        "brain",
        "injury",
        "scoliosis",
        "colitis",
        "syndrome",
        "disorder",
        "disease",
        "arthritis",
        "fatigue",
        "migraine",
        "asthma",
        "diabetes",
        "depression",
        "anxiety",
        "kidney",
        "cancer",
        "sleep",
        "apnea",
        "lung",
        "pulmonary",
        "renal",
        "rheumatoid",
        "obstructive",
        "and",
        "et",
        "en",
    ];
    // Numeric disease classifications expand in personal prose. A terminal
    // leading classifier may also attach without a recognized frame, while a
    // trailing classifier must be complete and terminal.
    const PERSONAL_CLASSIFIERS: &[&str] =
        &["type", "stage", "1", "2", "3", "4", "5", "i", "ii", "iii"];
    let personal_frames = personal_frame_flags(text, words);
    let starts: HashMap<usize, usize> = words
        .iter()
        .enumerate()
        .map(|(index, word)| (word.start, index))
        .collect();
    let ends: HashMap<usize, usize> = words
        .iter()
        .enumerate()
        .map(|(index, word)| (word.end, index))
        .collect();
    for span in spans
        .iter_mut()
        .filter(|span| span.kind == EntityKind::Health)
    {
        let Some(&mut_first) = starts.get(&span.start) else {
            continue;
        };
        let Some(&mut_last) = ends.get(&span.end) else {
            continue;
        };
        let frame_index = mut_first;
        let condition_last = mut_last;
        let mut first = mut_first;
        let mut last = mut_last;
        while first > 0 && last - first + 2 <= 6 && span.end - words[first - 1].start <= 60 {
            let prev = &words[first - 1];
            let coordinator_needs_peer = matches!(prev.folded.as_str(), "and" | "et" | "en")
                && !(first > 1 && CONDITION_WORDS.contains(&words[first - 2].folded.as_str()));
            let leading_classifier = PERSONAL_CLASSIFIERS.contains(&prev.folded.as_str())
                && (personal_frames[frame_index] || terminal_condition(text, words, last));
            if !valid_extension_gap(
                text,
                prev.end,
                words[first].start,
                false,
                leading_classifier,
            ) || coordinator_needs_peer
                || (PERSONAL_CLASSIFIERS.contains(&prev.folded.as_str()) && !leading_classifier)
                || (!MODIFIERS.contains(&prev.folded.as_str())
                    && !(personal_frames[frame_index]
                        && CONDITION_WORDS.contains(&prev.folded.as_str())))
            {
                break;
            }
            first -= 1;
        }
        while last + 1 < words.len()
            && last + 2 - first <= 6
            && words[last + 1].end - words[first].start <= 60
        {
            let next = &words[last + 1];
            let trailing_classifier =
                trailing_classifier_member(text, words, condition_last, last + 1);
            let coordinator_needs_peer = matches!(next.folded.as_str(), "and" | "et" | "en")
                && !(last + 2 < words.len()
                    && CONDITION_WORDS.contains(&words[last + 2].folded.as_str()));
            if !valid_extension_gap(
                text,
                words[last].end,
                next.start,
                trailing_classifier,
                false,
            ) || coordinator_needs_peer
                || (PERSONAL_CLASSIFIERS.contains(&next.folded.as_str())
                    && !personal_frames[frame_index]
                    && !trailing_classifier)
                || (!MODIFIERS.contains(&next.folded.as_str())
                    && !(personal_frames[frame_index]
                        && CONDITION_WORDS.contains(&next.folded.as_str()))
                    && !trailing_classifier)
            {
                break;
            }
            last += 1;
        }
        span.start = words[first].start;
        span.end = words[last].end;
    }
}

/// Gaps accepted while extending a condition: ordinary joins, one comma and
/// following spaces before a complete trailing classifier, or one line break
/// after a leading classifier. Sentence punctuation and blank lines never join.
fn valid_extension_gap(
    text: &str,
    from: usize,
    to: usize,
    comma_allowed: bool,
    newline_allowed: bool,
) -> bool {
    let Some(gap) = text.get(from..to) else {
        return false;
    };
    if gap.chars().any(|ch| matches!(ch, '.' | '!' | '?' | ';'))
        || gap.contains("\n\n")
        || gap.contains("\r\n\r\n")
    {
        return false;
    }
    if joins(text, from, to) {
        return !gap.contains(['\n', '\r']) || (newline_allowed && one_line_break(gap));
    }
    comma_allowed
        && gap.starts_with(',')
        && gap.len() > 1
        && gap[1..].chars().all(char::is_whitespace)
        && !gap.contains(['\n', '\r'])
}

fn one_line_break(gap: &str) -> bool {
    let mut chars = gap.chars().peekable();
    let mut breaks = 0;
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                breaks += 1;
            }
            '\n' => breaks += 1,
            ' ' | '\t' => {}
            _ => return false,
        }
        if breaks > 1 {
            return false;
        }
    }
    breaks == 1
}

fn classifier_word(word: &str) -> bool {
    matches!(
        word,
        "type" | "tipe" | "stage" | "stadium" | "1" | "2" | "3" | "4" | "5" | "i" | "ii" | "iii"
    )
}

fn terminal_condition(text: &str, words: &[Word], last: usize) -> bool {
    let end = words[last].end;
    let tail = &text[end..];
    if tail.len() > 60 {
        return false;
    }
    tail.trim_start_matches(char::is_whitespace)
        .chars()
        .next()
        .is_none_or(|ch| matches!(ch, '.' | '!' | '?' | ';' | ','))
        || (last + 1 < words.len()
            && matches!(
                words[last + 1].folded.as_str(),
                "and" | "or" | "et" | "ou" | "en" | "of"
            ))
}

fn trailing_classifier_member(
    text: &str,
    words: &[Word],
    condition_last: usize,
    member: usize,
) -> bool {
    if member <= condition_last || member >= words.len() {
        return false;
    }
    let start = if member > 0 && classifier_word(&words[member - 1].folded) {
        member - 1
    } else {
        member
    };
    if !matches!(
        words[start].folded.as_str(),
        "type" | "tipe" | "stage" | "stadium"
    ) {
        return false;
    }
    let number = start + 1;
    if number >= words.len()
        || !matches!(
            words[number].folded.as_str(),
            "1" | "2" | "3" | "4" | "5" | "i" | "ii" | "iii"
        )
    {
        return false;
    }
    if member != start && member != number {
        return false;
    }
    if member == number
        && !matches!(
            words[start].folded.as_str(),
            "type" | "tipe" | "stage" | "stadium"
        )
    {
        return false;
    }
    if start != condition_last + 1
        || !valid_extension_gap(
            text,
            words[condition_last].end,
            words[start].start,
            true,
            false,
        )
        || !joins(text, words[start].end, words[number].start)
    {
        return false;
    }
    let after = number + 1;
    terminal_condition(text, words, number)
        || (after < words.len()
            && matches!(
                words[after].folded.as_str(),
                "and" | "or" | "et" | "ou" | "en" | "of"
            ))
}

/// A medicine strength or test result next to a known health term is part of
/// the personal health value. Numbers and units never create spans alone.
fn extend_quantified_health(text: &str, words: &[Word], hits: &mut [Hit]) {
    const QUANTIFIED_TERMS: &[&str] = &[
        "metformin",
        "insulin",
        "amoxicillin",
        "sertraline",
        "citalopram",
        "escitalopram",
        "paroxetine",
        "venlafaxine",
        "duloxetine",
        "mirtazapine",
        "levothyroxine",
        "prednisone",
        "prednisolone",
        "ibuprofen",
        "paracetamol",
        "acetaminophen",
        "omeprazole",
        "pantoprazole",
        "lisinopril",
        "amlodipine",
        "losartan",
        "metoprolol",
        "salbutamol",
        "albuterol",
        "warfarin",
        "apixaban",
        "clopidogrel",
        "gabapentin",
        "tramadol",
        "morphine",
        "codeine",
        "oxycodone",
        "methotrexate",
        "tamoxifen",
        "hba1c",
        "cholesterol",
        "glycemie",
        "viral",
        "charge",
        "virale",
    ];
    let starts: HashMap<usize, usize> = words
        .iter()
        .enumerate()
        .map(|(index, word)| (word.start, index))
        .collect();
    let ends: HashMap<usize, usize> = words
        .iter()
        .enumerate()
        .map(|(index, word)| (word.end, index))
        .collect();
    for hit in hits
        .iter_mut()
        .filter(|hit| hit.span.kind == EntityKind::Health)
    {
        let Some(&index) = starts.get(&hit.span.start) else {
            continue;
        };
        let Some(&last) = ends.get(&hit.span.end) else {
            continue;
        };
        if !QUANTIFIED_TERMS.contains(&words[index].folded.as_str()) {
            continue;
        }
        if let Some(end) = quantity_end(text, words[last].end) {
            hit.span.end = end;
        }
    }
}

/// End of a directly attached numeric measurement with a recognised unit.
fn quantity_end(text: &str, from: usize) -> Option<usize> {
    const UNITS: &[&str] = &[
        "mg/dl",
        "mmol/l",
        "g/l",
        "copies/ml",
        "mcg",
        "µg",
        "μg",
        "units",
        "copies",
        "mg",
        "ml",
        "iu",
        "g",
        "%",
    ];
    let mut at = from;
    while let Some(ch) = text.get(at..)?.chars().next() {
        if ch.is_whitespace() || matches!(ch, ',' | ':' | '-' | '‐' | '‑' | '–') {
            at += ch.len_utf8();
            if at - from > 8 {
                return None;
            }
        } else {
            break;
        }
    }
    // One linking word may stand before the value: "HbA1c is 8.1 %".
    const LINKS: &[&str] = &["is", "was", "at", "of", "est", "à", "de"];
    let link_end = text[at..]
        .char_indices()
        .take(4)
        .find(|(_, ch)| !ch.is_alphabetic())
        .map(|(offset, _)| at + offset);
    if let Some(link_end) = link_end.filter(|&end| {
        end > at
            && LINKS.contains(&text[at..end].to_lowercase().as_str())
            && text[end..].starts_with(char::is_whitespace)
    }) {
        at = link_end;
        while let Some(ch) = text[at..].chars().next().filter(|ch| ch.is_whitespace()) {
            at += ch.len_utf8();
            if at - link_end > 8 {
                return None;
            }
        }
    }
    let number_start = at;
    while at - number_start < 16 && text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    if at == number_start {
        return None;
    }
    if text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    if text
        .as_bytes()
        .get(at)
        .is_some_and(|byte| matches!(byte, b'.' | b','))
        && text.as_bytes().get(at + 1).is_some_and(u8::is_ascii_digit)
    {
        at += 1;
        while at - number_start < 16 && text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if text.as_bytes().get(at).is_some_and(u8::is_ascii_digit) {
            return None;
        }
    }
    let unit_space_start = at;
    while text
        .get(at..)?
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
    {
        at += text[at..].chars().next()?.len_utf8();
        if at - unit_space_start > 8 {
            return None;
        }
    }
    for unit in UNITS {
        let Some(end) = at.checked_add(unit.len()) else {
            continue;
        };
        let Some(candidate) = text.get(at..end) else {
            continue;
        };
        if candidate.eq_ignore_ascii_case(unit)
            && !text
                .get(end..)?
                .chars()
                .next()
                .is_some_and(char::is_alphanumeric)
        {
            return Some(end);
        }
    }
    None
}

/// A maximal run of letters and digits, folded for matching.
struct Word {
    folded: String,
    start: usize,
    end: usize,
}

/// Split `text` into its words. Invisible and combining characters belong to
/// the word around them, and every other character ends a word.
fn words(text: &str) -> Vec<Word> {
    let mut words = Vec::new();
    let mut current: Option<Word> = None;
    for (offset, ch) in text.char_indices() {
        let end = offset + ch.len_utf8();
        if is_default_ignorable(ch) || is_combining_mark(ch) {
            if let Some(word) = current.as_mut() {
                word.end = end;
            }
        } else if ch.is_alphanumeric() && !is_han(ch) {
            let word = current.get_or_insert(Word {
                folded: String::new(),
                start: offset,
                end,
            });
            fold_into(&mut word.folded, ch);
            word.end = end;
        } else if let Some(word) = current.take() {
            words.push(word);
        }
    }
    words.extend(current);
    for word in &mut words {
        if let Some(folded) = lookalike_fold(&text[word.start..word.end]) {
            word.folded = folded;
        }
    }
    words
}

/// A Latin word written with Cyrillic or Greek look-alikes (`DIАВЕТЕS`), folded
/// with each look-alike read as its Latin letter (HEALTH-LABEL-1). `None` for a
/// word with no ASCII letter, no Cyrillic or Greek letter, or a letter that has
/// no Latin look-alike: a Cyrillic or Greek word keeps its letters.
fn lookalike_fold(raw: &str) -> Option<String> {
    let foreign = |ch: char| is_cyrillic(ch) || is_greek(ch);
    if !raw.chars().any(|ch| ch.is_ascii_alphabetic()) || !raw.chars().any(foreign) {
        return None;
    }
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if foreign(ch) {
            let mut lower = ch.to_lowercase();
            let single = lower.next().filter(|_| lower.next().is_none());
            fold_into(
                &mut out,
                homoglyph(ch).or_else(|| single.and_then(homoglyph))?,
            );
        } else if !is_default_ignorable(ch) {
            fold_into(&mut out, ch);
        }
    }
    Some(out)
}

/// The traditional-to-simplified pairs of the Han terms, from OpenCC (see the
/// header of `data/han-fold-v1.tsv`), sorted by the traditional character. Both
/// sides are three bytes in UTF-8, so a folded text keeps every byte offset.
const HAN_FOLD_DATA: &str = include_str!("../../data/han-fold-v1.tsv");

/// The parsed, sorted table, built once.
fn han_fold_pairs() -> &'static [(char, char)] {
    static PAIRS: OnceLock<Vec<(char, char)>> = OnceLock::new();
    PAIRS.get_or_init(|| {
        // A traditional character with two simplified forms keeps its TS pair: the
        // fold reads traditional as simplified, so TS is the authority (rank 0).
        let mut ranked: Vec<(char, char, u8)> = HAN_FOLD_DATA
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let mut fields = line.split('\t');
                let traditional = fields.next()?.chars().next()?;
                let simplified = fields.next()?.chars().next()?;
                let rank = if fields.next() == Some("ST") { 1 } else { 0 };
                Some((traditional, simplified, rank))
            })
            .collect();
        ranked.sort_unstable_by_key(|&(traditional, _, rank)| (traditional, rank));
        ranked.dedup_by_key(|&mut (traditional, _, _)| traditional);
        ranked
            .into_iter()
            .map(|(traditional, simplified, _)| (traditional, simplified))
            .collect()
    })
}

/// The simplified form of `ch`, or `ch` itself when it has none in the table.
fn han_fold(ch: char) -> char {
    let pairs = han_fold_pairs();
    pairs
        .binary_search_by_key(&ch, |&(traditional, _)| traditional)
        .map_or(ch, |index| pairs[index].1)
}

/// The Han text as the Han terms read it: a traditional character reads as its
/// simplified form, and an invisible character or a space is dropped, so
/// `糖\u{200B}尿 病` reads `糖尿病`. Each kept character remembers where it sits in
/// the original text.
struct HanView {
    text: String,
    /// Per kept character: its byte span in `text`, then in the original.
    cuts: Vec<(usize, usize, usize, usize)>,
}

impl HanView {
    fn new(text: &str) -> Self {
        let mut view = HanView {
            text: String::with_capacity(text.len()),
            cuts: Vec::new(),
        };
        for (start, ch) in text.char_indices() {
            if is_default_ignorable(ch) || ch.is_whitespace() || is_han_joiner(ch) {
                continue;
            }
            let from = view.text.len();
            view.text.push(han_fold(ch));
            view.cuts
                .push((from, view.text.len(), start, start + ch.len_utf8()));
        }
        view
    }

    /// The original byte span of the view span `start..end`, when both ends
    /// fall on kept characters (a Han match always does).
    fn original(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        let first = self.cuts.binary_search_by_key(&start, |cut| cut.0).ok()?;
        let last = self.cuts.binary_search_by_key(&end, |cut| cut.1).ok()?;
        Some((self.cuts[first].2, self.cuts[last].3))
    }
}

/// Punctuation that a Han term may be split by, as in 糖·尿·病 or 糖-尿-病: middle
/// dots and the hyphen family. The view drops it, so the term still matches.
fn is_han_joiner(ch: char) -> bool {
    matches!(ch, '·' | '・' | '･' | '‧' | '-' | '‐' | '‑' | '–' | '—')
}

/// Whether `ch` is a Han ideograph. Han characters end a Latin word.
fn is_han(ch: char) -> bool {
    matches!(
        ch as u32,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x2_0000..=0x2_EBEF
    )
}

/// Append the matching form of `ch`: NFKD, combining marks dropped, lowercase.
fn fold_into(out: &mut String, ch: char) {
    for decomposed in ch.nfkd() {
        if !is_combining_mark(decomposed) {
            out.extend(decomposed.to_lowercase());
        }
    }
}

/// The matching form of a whole string.
fn fold_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        fold_into(&mut out, ch);
    }
    out
}

/// Whether the text between two consecutive words is a join a multi-word term
/// may cross: whitespace, a hyphen, an apostrophe or an invisible character.
fn joins(text: &str, from: usize, to: usize) -> bool {
    from < to
        && text[from..to].chars().all(|ch| {
            ch.is_whitespace()
                || is_default_ignorable(ch)
                || matches!(ch, '-' | '\'' | '\u{2019}' | '\u{02BC}')
        })
}

/// How a non-stem word of a lexicon term inflects in its language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Inflection {
    /// French and Afrikaans: the base word, with its plural or feminine `s`,
    /// `es` or `e`.
    Plain,
    /// English: the plain forms, and on the final word also the `y` to `ies`,
    /// `ied` and `-ing` forms, the `-ed` and `-d`, `-ing` and `-ation` forms of a
    /// verb or noun stem (see [`english_forms`]).
    English,
    /// Slovene: the stem (the base minus its final vowel) with a case ending.
    Slovene,
    /// Hungarian: the base with case and possessive suffixes, with the linking
    /// and assimilation rules.
    Hungarian,
    /// A brand or INN name (lang `xx`): the name with a suffix of four letters or
    /// fewer.
    Name,
}

/// One word of a lexicon term. `stem` marks a prefix match.
struct Token {
    text: String,
    stem: bool,
    inflection: Inflection,
    /// The words this row must not match: `FIV` is `FIV`, never `five`
    /// (K-OVERMASK-FIVE).
    excluded: Vec<String>,
}

/// Slovene endings that a noun or an adjective takes after its stem, folded.
const SL_ENDINGS: &[&str] = &[
    "", "a", "e", "i", "o", "u", "om", "em", "ijo", "ije", "iji", "ja", "ju", "jo", "ama", "ah",
    "ih", "mi", "ov", "ev", "ega", "emu", "im", "on",
];

/// The endings an earlier word of a multi-word Slovene term takes: its base form,
/// or an adjective ending.
const SL_ADJECTIVE_ENDINGS: &[&str] = &["", "o", "e", "a", "i", "ega", "emu", "im", "on"];

/// The shortest Slovene stem that takes inflection, in characters: a shorter stem
/// matches its base word only.
const MIN_INFLECTED_STEM: usize = 3;

/// The shortest Hungarian base that takes inflection, in characters: a three-letter
/// acronym such as HIV takes none (hívják is not HIV + jak).
const MIN_HUNGARIAN_BASE: usize = 4;

/// Hungarian case endings, in their accented canonical form (they are compared
/// folded).
const HU_CASE: &[&str] = &[
    "", "t", "ot", "et", "át", "ét", "on", "en", "ön", "ban", "ben", "ba", "be", "ból", "ből",
    "ról", "ről", "tól", "től", "ra", "re", "hoz", "hez", "höz", "nak", "nek", "val", "vel", "mal",
    "mel", "sal", "sel", "szal", "szel", "nyel", "nyal", "ral", "rel", "kal", "kel", "ként", "ig",
    "os", "ös", "ok", "ek", "k",
];

/// Hungarian possessive suffixes, which come before a case ending.
const HU_POSS: &[&str] = &[
    "a", "e", "ja", "je", "m", "om", "am", "em", "unk", "ünk", "tok", "tek", "juk", "jük",
];

/// The folded forms of a list of Hungarian suffixes, built once.
fn hu_folded(list: &'static [&'static str]) -> Vec<String> {
    list.iter().map(|ending| fold_str(ending)).collect()
}

/// Whether a folded Hungarian ending is a case ending, or a possessive followed
/// by a case ending (`-om` + `-ról`, `-ja` + `-val`), or a bare possessive.
fn hungarian_ending(rest: &str) -> bool {
    static CASES: OnceLock<Vec<String>> = OnceLock::new();
    static POSSESSIVES: OnceLock<Vec<String>> = OnceLock::new();
    let cases = CASES.get_or_init(|| hu_folded(HU_CASE));
    let possessives = POSSESSIVES.get_or_init(|| hu_folded(HU_POSS));
    cases.iter().any(|case| case == rest)
        || possessives.iter().any(|poss| {
            rest == poss.as_str()
                || rest
                    .strip_prefix(poss.as_str())
                    .is_some_and(|case| cases.iter().any(|c| c == case))
        })
}

/// The Hungarian stem of a base: a `-ny` base loses its `y` before a suffix
/// (fény → fénnyel), every other base is its own stem.
fn hungarian_stem(base: &str) -> &str {
    match base.strip_suffix("ny") {
        Some(_) => &base[..base.len() - 1],
        None => base,
    }
}

/// Whether a folded word is a Hungarian inflection of a folded base: the base, its
/// stem with a suffix, or a doubled final consonant with a suffix (sérv → sérvvel).
fn hungarian_inflected(word: &str, base: &str) -> bool {
    if word == base {
        return true;
    }
    if let Some(rest) = word.strip_prefix(hungarian_stem(base)) {
        if hungarian_ending(rest) {
            return true;
        }
    }
    if let (Some(last), Some(rest)) = (base.chars().last(), word.strip_prefix(base)) {
        let consonant = last.is_ascii_alphabetic() && !"aeiou".contains(last);
        if consonant {
            if let Some(tail) = rest.strip_prefix(last) {
                // -val/-vel assimilate to the doubled consonant: lázzal.
                return hungarian_ending(tail) || matches!(tail, "al" | "el");
            }
        }
    }
    false
}

/// The Slovene stem of a base: the base minus its final vowel.
fn slovene_stem(base: &str) -> &str {
    match base.chars().last() {
        Some('a' | 'e' | 'i' | 'o' | 'u') => &base[..base.len() - 1],
        _ => base,
    }
}

/// Whether a folded word is the base word with a plural or feminine `s`, `es` or `e`.
fn plain_match(word: &str, base: &str) -> bool {
    word.strip_prefix(base)
        .is_some_and(|rest| rest.is_empty() || matches!(rest, "s" | "es" | "e"))
}

/// The plain forms of a base word, as [`plain_match`] reads them.
fn plain_forms(base: &str) -> Vec<String> {
    vec![
        base.to_string(),
        format!("{base}s"),
        format!("{base}es"),
        format!("{base}e"),
    ]
}

/// The forms an English final word takes: the plain forms, then `y` to `ies` and
/// `ied` (therapy, miscarry), the `-ed` and `-d` (addict, disable), the `-ing`
/// (overdose, miscarry), and for a stem in `-ize` or `-ise` the `-ation(s)` noun
/// (hospitalize). A word that is not a stem of a lexicon term is not a form.
fn english_forms(base: &str) -> Vec<String> {
    let mut forms = plain_forms(base);
    if let Some(stem) = base.strip_suffix('y') {
        forms.push(format!("{stem}ies"));
        forms.push(format!("{stem}ied"));
        forms.push(format!("{base}ing"));
    } else if let Some(stem) = base.strip_suffix('e') {
        forms.push(format!("{base}d"));
        forms.push(format!("{stem}ing"));
        if base.ends_with("ize") || base.ends_with("ise") {
            forms.push(format!("{stem}ation"));
            forms.push(format!("{stem}ations"));
        }
    } else {
        forms.push(format!("{base}ed"));
        forms.push(format!("{base}ing"));
    }
    forms
}

/// How a token enters the index: an exact set of forms, or a prefix (a stem).
enum Index {
    Exact(Vec<String>),
    Prefix(String),
}

impl Token {
    /// Whether a folded word is this token. `last` is set for the final word of a
    /// term: an earlier word takes only its base form (plus an adjective ending in
    /// Slovene), the last word takes the full inflection.
    fn matches(&self, word: &str, last: bool) -> bool {
        if self.stem {
            return word.starts_with(&self.text);
        }
        if last && self.excluded.iter().any(|excluded| excluded == word) {
            // The row excepts this word: `FIV` is `FIV`, never `five`.
            return false;
        }
        match self.inflection {
            Inflection::Plain => plain_match(word, &self.text),
            Inflection::English => {
                plain_match(word, &self.text)
                    || (last && english_forms(&self.text).iter().any(|form| form == word))
            }
            Inflection::Slovene => {
                if word == self.text {
                    return true;
                }
                let stem = slovene_stem(&self.text);
                if stem.chars().count() < MIN_INFLECTED_STEM {
                    return false;
                }
                let endings = if last {
                    SL_ENDINGS
                } else {
                    SL_ADJECTIVE_ENDINGS
                };
                word.strip_prefix(stem)
                    .is_some_and(|rest| endings.contains(&rest))
            }
            Inflection::Hungarian => {
                if last && self.text.chars().count() >= MIN_HUNGARIAN_BASE {
                    hungarian_inflected(word, &self.text)
                } else {
                    word == self.text
                }
            }
            Inflection::Name => word.strip_prefix(self.text.as_str()).is_some_and(|rest| {
                rest.chars().count() <= 4 && rest.chars().all(char::is_alphabetic)
            }),
        }
    }

    /// The forms of this token, without the words its row excepts.
    fn kept(&self, forms: Vec<String>) -> Vec<String> {
        forms
            .into_iter()
            .filter(|form| !self.excluded.iter().any(|excluded| excluded == form))
            .collect()
    }

    /// How this token is indexed: its exact forms, or the prefix that every
    /// inflected form starts with.
    fn index(&self) -> Index {
        if self.stem {
            return Index::Prefix(self.text.clone());
        }
        match self.inflection {
            Inflection::Plain => Index::Exact(self.kept(plain_forms(&self.text))),
            // A superset: `matches` checks the final-word forms for the last word only.
            Inflection::English => Index::Exact(self.kept(english_forms(&self.text))),
            Inflection::Slovene => {
                let stem = slovene_stem(&self.text);
                if stem.chars().count() < MIN_INFLECTED_STEM {
                    Index::Prefix(self.text.clone())
                } else {
                    Index::Prefix(stem.to_string())
                }
            }
            Inflection::Hungarian => Index::Prefix(hungarian_stem(&self.text).to_string()),
            Inflection::Name => Index::Prefix(self.text.clone()),
        }
    }
}

/// A lexicon entry of one or more words.
struct Phrase {
    kind: EntityKind,
    tokens: Vec<Token>,
    /// An ambiguous abbreviation: it stands only next to a health anchor.
    contextual: bool,
    lang: &'static str,
}

/// A lexicon hit. `contextual` marks an ambiguous abbreviation, which the
/// caller keeps only when a health anchor shares its sentence.
struct Hit {
    span: Span,
    contextual: bool,
    /// The language of the row that matched: an ambiguous abbreviation takes its
    /// anchor from the same language only.
    lang: &'static str,
}

/// The static name of a lexicon language (`xx` for a brand or INN name).
fn language(lang: &str) -> &'static str {
    match lang {
        "fr" => "fr",
        "en" => "en",
        "af" => "af",
        "hu" => "hu",
        "sl" => "sl",
        "zh" => "zh",
        _ => "xx",
    }
}

/// How far the sentence check looks each side of a contextual hit, in bytes:
/// a sentence longer than this is cut, which keeps the scan linear.
const SENTENCE_WINDOW: usize = 512;

/// Whether a character ends a sentence for the health-anchor check.
fn is_sentence_end(ch: char) -> bool {
    matches!(ch, '.' | '!' | '?' | ';' | '\n' | '。' | '！' | '？' | '；')
}

/// The largest character boundary at or before `at`.
fn char_floor(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// The smallest character boundary at or after `at`.
fn char_ceil(text: &str, mut at: usize) -> usize {
    while at < text.len() && !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

/// Whether a health anchor (a strong term or a cue, by start offset in
/// `anchors`) starts in the sentence around `span`, outside the span itself: a
/// disease name never anchors itself (`Mark's disease`).
fn cued(text: &str, span: Span, anchors: &[usize]) -> bool {
    let from = char_floor(text, span.start.saturating_sub(SENTENCE_WINDOW));
    let low = text[from..span.start]
        .char_indices()
        .rev()
        .find(|(_, ch)| is_sentence_end(*ch))
        .map_or(from, |(at, ch)| from + at + ch.len_utf8());
    let to = char_ceil(text, (span.end + SENTENCE_WINDOW).min(text.len()));
    let high = text[span.end..to]
        .char_indices()
        .find(|(_, ch)| is_sentence_end(*ch))
        .map_or(to, |(at, _)| span.end + at);
    let first = anchors.partition_point(|&start| start < low);
    anchors[first..]
        .iter()
        .take_while(|&&start| start < high)
        .any(|&start| start < span.start || start >= span.end)
}

/// Hungarian heads that follow a `rák` in a compound: rákszűrés, rákkutatás.
const HU_RAK_HEADS: &[&str] = &[
    "szűrés",
    "szűrő",
    "kutatás",
    "kutató",
    "kezel",
    "sejt",
    "megbetegedés",
    "betegség",
    "beteg",
    "ellenes",
    "gyógyszer",
    "műtét",
    "operáció",
    "diagnózis",
    "diagnosztika",
    "kockázat",
    "prevenció",
    "túlél",
    "halál",
    "elhalálozás",
    "statisztika",
    "központ",
    "intézet",
    "klinika",
    "orvos",
    "ellátás",
    "terápia",
    "szövet",
    "kórház",
    "tünet",
    "vizsgálat",
    "sugár",
    "kemoterápia",
];

/// Whether a raw, lower-cased, NFC word is Hungarian `rák` (cancer), with the
/// accent. A `rák` that starts the word is followed by a health head or a case
/// ending (rákszűrés, rákból). A `rák` that ends a compound has a root of three
/// letters or more (méhnyakrák, vastagbélrák). Bare `rak` and `árak` never match,
/// and neither does a place name (Rákospalota, Rákóczi).
fn hu_rak_word(word: &str) -> bool {
    if let Some(rest) = word.strip_prefix("rák") {
        return HU_RAK_HEADS.iter().any(|head| rest.starts_with(head))
            || hungarian_ending(&fold_str(rest));
    }
    match word.find("rák") {
        Some(index) => {
            let root = &word[..index];
            let ending = &word[index + "rák".len()..];
            root.chars().count() >= 3
                && root.chars().all(char::is_alphabetic)
                && hungarian_ending(&fold_str(ending))
        }
        None => false,
    }
}

/// Push the Hungarian `rák` words, matched on the raw word so the accent counts.
fn push_hu_rak(text: &str, words: &[Word], out: &mut Vec<Hit>) {
    for word in words {
        let raw: String = text[word.start..word.end].to_lowercase().nfc().collect();
        // Rákos-patak is a stream: the word before `-patak` is a place, not a case.
        let place = text[word.end..].starts_with("-patak");
        if raw.contains("rák") && !place && hu_rak_word(&raw) {
            out.push(Hit {
                span: Span::new(EntityKind::Health, word.start, word.end, SCORE, NAME),
                contextual: false,
                lang: "hu",
            });
        }
    }
}

/// Disease words that make the capitalised word before them the name of a
/// disease: `Mist Fever`, `Köd-láz`, `Grys-koors`. Folded; `true` when the name
/// must be joined by a hyphen (Hungarian, Afrikaans), `contextual` when a health
/// anchor must share the sentence: a disease word carries the sentence on its
/// own, only a fever word asks for one (`Gold Fever` is a crowd, not a patient).
const DISEASE_HEADS: &[(&str, &[&str], bool, bool)] = &[
    ("en", &["fever"], false, true),
    ("en", &["disease", "syndrome"], false, false),
    // HEALTH-EPONYM-1: `Hashimoto thyroiditis`, `Bell's palsy`, `Hodgkin lymphoma`.
    (
        "en",
        &["palsy", "lymphoma", "thyroiditis", "chorea", "sarcoma"],
        false,
        false,
    ),
    ("hu", &["laz"], true, true),
    ("hu", &["betegseg", "szindroma", "kor"], true, false),
    ("af", &["griep", "koors"], true, true),
    ("af", &["siekte", "sindroom"], true, false),
];

/// A health hit on `from..to`.
fn health(from: usize, to: usize, contextual: bool, lang: &'static str) -> Hit {
    let span = Span::new(EntityKind::Health, from, to, SCORE, NAME);
    Hit {
        span,
        contextual,
        lang,
    }
}

/// French disease words that a `de` and a capitalised name follow: `maladie de
/// Brume`, `syndrome d'Ombrelune`. Folded, with the same anchor rule as
/// [`DISEASE_HEADS`]: `fièvre de` asks for a health anchor, the two disease
/// words do not.
const DISEASE_LEADS: &[(&str, bool)] = &[
    ("maladie", false),
    ("syndrome", false),
    ("fievre", true),
    // HEALTH-EPONYM-1: `thyroïdite de Hashimoto`, `lymphome de Hodgkin`.
    ("thyroidite", false),
    ("lymphome", false),
    ("choree", false),
    ("sarcome", false),
];

/// Folded words that are never a disease name: articles, determiners and
/// pronouns that start a sentence (`This disease`, `No fever`).
const NOT_A_NAME: &[&str] = &[
    "the", "a", "an", "this", "that", "these", "those", "my", "his", "her", "our", "their", "your",
    "its", "no", "any", "some", "which", "what", "every", "each", "one", "such", "same", "az",
    "egy", "die", "n", "hierdie", "daardie", "le", "la", "les", "l", "un", "une", "du", "des",
    "de", "ce", "cette",
];

/// Folded honorifics: the word after one is a person (`Dr Brume`), never a disease.
const HONORIFICS: &[&str] = &[
    "dr", "mr", "mrs", "ms", "miss", "prof", "mme", "mlle", "m", "me", "pr", "mev", "mnr", "dkt",
];

/// Folded words that name a figurative syndrome, never a patient's condition:
/// `Imposter syndrome` is a self-doubt habit, `Stockholm syndrome` a novel
/// cliché, `China syndrome` a building's nickname. They sit where the rules
/// above expect the name of a disease — the capitalised word before
/// `syndrome`, or after a French `de` — and nothing else in the sentence says
/// otherwise. `tall poppy` and `shiny object` need no entry: the word before
/// their `syndrome` is lower-case and never a name.
///
/// The list is idiom words only, and the guard that reads it is scoped to the
/// one shape the idiom takes (see [`figurative_syndrome`]): a real disease
/// whose name is also a place or a person must never land here. `Down`,
/// `Tourette`, `Asperger`, `Sjögren`, `Cushing` and `Guillain-Barré` all stay
/// masked, and so does every invented name this pass is for (`Mist Fever`,
/// `Grootrivier-sindroom`, `Grey-China syndrome`).
const FIGURATIVE_SYNDROMES: &[&str] = &["imposter", "impostor", "stockholm", "china", "poppy"];

/// Whether the name a disease word would mint is one of the idioms in `idioms`,
/// and so is not a patient's condition. The head decides, because only the head
/// tells an idiom from a disease: `Stockholm syndrome` is a cliché, while
/// `Stockholm-szindróma`, `Stockholm fever`, `Stockholm-sindroom` and
/// `Stockholm-koors` are names like any other. So is the same word before any
/// disease head but `syndrome` (`China Fever`, `Poppy disease`).
///
/// The name must also be the one word the rule resolved: a hyphen joins a
/// longer name (`Grey-China syndrome`, `Grey-Wing Syndrome`), and that name is
/// a disease like every other invented one.
fn figurative_syndrome(
    head: &str,
    idioms: &[&str],
    words: &[Word],
    first: usize,
    last: usize,
) -> bool {
    head == "syndrome" && first == last && idioms.contains(&words[last].folded.as_str())
}

/// The French `de` form carries one idiom only. `Le syndrome de Stockholm` is
/// a cliché of the novel, and the other four are diseases until a name says
/// otherwise: #202 masks `syndrome de Chine` and `syndrome d'Imposter` on
/// purpose (CHANGES ad205414), and this guard must not take that back.
const FRENCH_FIGURATIVE_SYNDROMES: &[&str] = &["stockholm"];

/// How far back a cue frame is looked for before a fever name, in bytes: a
/// constant, so the frame check keeps the scan linear.
const FRAME_WINDOW: usize = 64;

/// Folded line labels that make the fever name right after their colon the
/// record's health value: `Condition: Mist Fever`, `Toestand: As-koors`,
/// `Igazolás: Köd-láz`. #202 took these words off the sentence-wide cue list,
/// where they anchored idioms (`Market conditions: Crypto Fever`); as the
/// whole label of their own line they anchor only the name they introduce.
const FRAME_LABELS: &[&str] = &[
    "condition",
    "medical condition",
    "certificate",
    "medical certificate",
    "certificat",
    "certificat medical",
    "igazolas",
    "orvosi igazolas",
    "toestand",
    "mediese toestand",
];

/// Folded `certificate for` frames: the name after them, or after one
/// determiner, is what the certificate is for.
const FRAME_FOR: &[(&str, &str)] = &[("certificate", "for"), ("certificat", "pour")];

/// Folded determiners a `certificate for` frame may cross.
const FRAME_DETERMINERS: &[&str] = &[
    "a", "an", "the", "his", "her", "their", "my", "your", "our", "la", "le", "l", "sa", "son",
];

/// Folded words that make a certificate no health paper: `gift certificate`,
/// `SSL certificate`.
const FRAME_NOT_HEALTH: &[&str] = &["gift", "ssl", "tls"];

/// Start of the line label and colon before `start`, when the whole label is
/// in [`FRAME_LABELS`] (a list bullet aside).
fn labelled(text: &str, start: usize) -> Option<usize> {
    let from = char_floor(text, start.saturating_sub(FRAME_WINDOW));
    let window = text[from..start].trim_end_matches(char::is_whitespace);
    let (window, bold_colon) = window
        .strip_suffix("**")
        .map_or((window, false), |w| (w, true));
    let head = window.strip_suffix([':', '\u{ff1a}', '-'])?.trim_end();
    let line = head
        .char_indices()
        .rev()
        .find(|(_, ch)| is_sentence_end(*ch))
        .map(|(at, ch)| &head[at + ch.len_utf8()..])
        .or((from == 0).then_some(head));
    let label = line?.trim().trim_start_matches(['-', '\u{2022}']).trim();
    let label = label.strip_prefix("* ").unwrap_or(label).trim();
    let start = from + head.len() - label.len();
    let label = if let Some(bold) = label.strip_prefix("**") {
        if bold_colon {
            bold
        } else {
            bold.strip_suffix("**")?
        }
    } else if bold_colon {
        return None;
    } else {
        label
    };
    FRAME_LABELS
        .contains(&fold_str(label.trim()).as_str())
        .then_some(start)
}

/// Start of `certificate for` before the name at `first`, optionally crossing
/// one determiner (`certificate for his Mist Fever`).
fn certificate_for(text: &str, words: &[Word], first: usize) -> Option<usize> {
    let mut at = first;
    if at > 0
        && FRAME_DETERMINERS.contains(&words[at - 1].folded.as_str())
        && joins(text, words[at - 1].end, words[at].start)
    {
        at -= 1;
    }
    if at < 2 {
        return None;
    }
    let (cert, prep) = (&words[at - 2], &words[at - 1]);
    let matched = FRAME_FOR
        .iter()
        .any(|(c, p)| plain_match(&cert.folded, c) && prep.folded == *p)
        && joins(text, cert.end, prep.start)
        && joins(text, prep.end, words[at].start)
        && !(at > 2 && FRAME_NOT_HEALTH.contains(&words[at - 3].folded.as_str()));
    matched.then_some(cert.start)
}

/// Start of the Hungarian certificate the name on `first..=last` is for:
/// `igazolást kér a Köd-láz miatt`, the `igazolás` at most three
/// words before the name in the same sentence, `miatt` right after it.
fn igazolas_miatt(text: &str, words: &[Word], first: usize, last: usize) -> Option<usize> {
    if !words.get(last + 1).is_some_and(|w| w.folded == "miatt") {
        return None;
    }
    words[first.saturating_sub(3)..first]
        .iter()
        .find(|w| {
            w.folded.starts_with("igazolas")
                && !text[w.end..words[first].start].contains(is_sentence_end)
        })
        .map(|w| w.start)
}

/// Start of a cue #202 dropped that frames the disease name itself. The
/// caller collects frames separately, retaining only independent name anchors.
fn framed(text: &str, words: &[Word], first: usize, last: usize) -> Option<usize> {
    labelled(text, words[first].start)
        .or_else(|| certificate_for(text, words, first))
        .or_else(|| igazolas_miatt(text, words, first, last))
}

/// The Afrikaans disease heads that a `se` joins to the name before it, both
/// hyphenated and space-joined: `Down se sindroom`, `Addison se siekte`.
const AF_SE_HEADS: &[&str] = &["siekte", "sindroom"];

/// The most hyphen-joined words in a disease name (`Grey-Wing`).
const MAX_NAME_WORDS: usize = 3;

/// A name candidate: letters, at least two characters, no determiner. Case
/// heuristics apply unless this pass emits only validated cue frames.
fn name_like(text: &str, word: &Word, frame_only: bool) -> bool {
    let raw = &text[word.start..word.end];
    (frame_only || raw.chars().next().is_some_and(char::is_uppercase))
        && raw.chars().count() >= 2
        && raw
            .chars()
            .all(|ch| ch.is_alphabetic() || is_default_ignorable(ch) || is_combining_mark(ch))
        && (frame_only || raw.chars().any(char::is_lowercase))
        && !NOT_A_NAME.contains(&word.folded.as_str())
}

/// Whether the text between two words is a single hyphen.
fn hyphen(text: &str, from: usize, to: usize) -> bool {
    matches!(&text[from..to], "-" | "\u{2010}" | "\u{2011}")
}

/// The first word of the disease name that ends at word `last`: hyphen-joined
/// name-like words, at most [`MAX_NAME_WORDS`], none after an honorific.
fn name_start(text: &str, words: &[Word], last: usize, frame_only: bool) -> Option<usize> {
    if !name_like(text, &words[last], frame_only) {
        return None;
    }
    let mut first = last;
    while first > 0
        && last - first + 1 < MAX_NAME_WORDS
        && hyphen(text, words[first - 1].end, words[first].start)
        && name_like(text, &words[first - 1], frame_only)
    {
        first -= 1;
    }
    let titled = first > 0 && {
        let before = &words[first - 1];
        let gap = &text[before.end..words[first].start];
        (joins(text, before.end, words[first].start) || gap.starts_with('.'))
            && HONORIFICS.contains(&before.folded.as_str())
    };
    (!titled).then_some(first)
}

/// Push the invented or rare disease names a disease word reveals: a name before
/// `fever`, `disease`, `-láz` or `-koors` (with an English possessive `'s` and
/// the Afrikaans `se`), and a name after the French `maladie de`. The span covers
/// name and disease word. A fever word needs a health term or cue in its
/// sentence; a disease word stands on its own.
fn push_disease_names(text: &str, words: &[Word], out: &mut Vec<Hit>, frame_only: bool) {
    for (index, word) in words.iter().enumerate() {
        let head = DISEASE_HEADS
            .iter()
            .find_map(|(lang, cues, hyphenated, contextual)| {
                let cue = cues.iter().copied().find(|cue| match *lang {
                    // `kór` (disease) keeps its accent: `Árpád-kor` is an era.
                    "hu" if *cue == "kor" => {
                        hungarian_inflected(&word.folded, cue)
                            && text[word.start..word.end].to_lowercase().starts_with("kór")
                    }
                    "hu" => hungarian_inflected(&word.folded, cue),
                    _ => plain_match(&word.folded, cue),
                })?;
                Some((*lang, *hyphenated, *contextual, cue))
            });
        if let Some((lang, hyphenated, contextual, cue)) = head {
            let mut last = index.checked_sub(1);
            if let Some(at) = last {
                // `Down se sindroom`, `Addison se siekte`: the af disease heads
                // take the name through a `se`, and are space-joined to it,
                // while the other heads are hyphen-joined.
                let af_se = lang == "af"
                    && AF_SE_HEADS.iter().any(|cue| plain_match(&word.folded, cue))
                    && words[at].folded == "se";
                let joined = if hyphenated && !af_se {
                    hyphen(text, words[at].end, word.start)
                } else {
                    joins(text, words[at].end, word.start)
                };
                last = joined.then_some(at);
            }
            // `Brume's disease`: the `s` is the possessive of the name before it.
            if let Some(at) = last.filter(|&at| at > 0 && lang == "en" && words[at].folded == "s") {
                let between = &text[words[at - 1].end..words[at].start];
                last = matches!(between, "'" | "\u{2019}").then_some(at - 1);
            }
            // `Down se sindroom`: the `se` joins the name to the word.
            if let Some(at) = last.filter(|&at| at > 0 && lang == "af" && words[at].folded == "se")
            {
                last = joins(text, words[at - 1].end, words[at].start).then_some(at - 1);
            }
            if let Some(at) = last {
                if let Some(first) = name_start(text, words, at, frame_only) {
                    // `Stockholm syndrome` is a cliché, `Stockholm-szindróma`
                    // a patient: the head, not the word, decides.
                    if !figurative_syndrome(cue, FIGURATIVE_SYNDROMES, words, first, at) {
                        if frame_only {
                            if let Some(start) = framed(text, words, first, index) {
                                out.push(health(start, word.end, false, lang));
                            }
                        } else {
                            out.push(health(words[first].start, word.end, contextual, lang));
                        }
                    }
                }
            }
        }
        let lead = DISEASE_LEADS
            .iter()
            .find(|(lead, _)| plain_match(&word.folded, lead));
        if let Some(&(head, contextual)) = lead {
            if index > 0 && words[index - 1].folded == "assurance" {
                continue;
            }
            let (Some(de), Some(name)) = (words.get(index + 1), words.get(index + 2)) else {
                continue;
            };
            if !matches!(de.folded.as_str(), "de" | "d" | "du")
                || !joins(text, word.end, de.start)
                || !joins(text, de.end, name.start)
                || !name_like(text, name, frame_only)
                || HONORIFICS.contains(&name.folded.as_str())
            {
                continue;
            }
            let mut last = index + 2;
            while last + 1 < words.len()
                && last - index < 1 + MAX_NAME_WORDS
                && hyphen(text, words[last].end, words[last + 1].start)
                && name_like(text, &words[last + 1], frame_only)
            {
                last += 1;
            }
            if !figurative_syndrome(head, FRENCH_FIGURATIVE_SYNDROMES, words, index + 2, last) {
                if frame_only {
                    if let Some(start) = framed(text, words, index, last) {
                        out.push(health(start, words[last].end, false, "fr"));
                    }
                } else {
                    out.push(health(word.start, words[last].end, contextual, "fr"));
                }
            }
        }
    }
}

/// Folded eponyms whose possessive alone names the condition (`I have
/// Hashimoto's`). `Alzheimer`, `Parkinson` and `Crohn` are lexicon terms.
const EPONYM_POSSESSIVES: &[&str] = &[
    "hashimoto",
    "asperger",
    "tourette",
    "huntington",
    "raynaud",
    "addison",
    "cushing",
    "meniere",
    "hodgkin",
];

/// Folded words that may follow a possessive used alone: it owns no noun.
const AFTER_ALONE: &[&str] = &[
    "and", "or", "but", "so", "since", "for", "too", "as", "which", "that", "now", "again", "et",
    "ou", "mais", "donc", "depuis",
];

/// Folded words before a possessive that make it a place (`at Hashimoto's`).
const PLACE_BEFORE: &[&str] = &["at", "chez"];

/// Push an eponym's possessive used alone (`Our son has Asperger's, so…`):
/// the clause ends after it or a linking word follows. A noun after it (`Ms
/// Hashimoto's invoice`), an honorific or a place word before it keeps its text.
fn push_eponym_possessives(text: &str, words: &[Word], out: &mut Vec<Hit>) {
    for (index, word) in words.iter().enumerate() {
        if !EPONYM_POSSESSIVES.contains(&word.folded.as_str()) || !name_like(text, word, false) {
            continue;
        }
        let Some(s) = words
            .get(index + 1)
            .filter(|s| s.folded == "s" && matches!(&text[word.end..s.start], "'" | "\u{2019}"))
        else {
            continue;
        };
        if let Some(before) = index.checked_sub(1).map(|at| &words[at]) {
            let gap = &text[before.end..word.start];
            let folded = before.folded.as_str();
            if (joins(text, before.end, word.start) || gap.starts_with('.'))
                && (HONORIFICS.contains(&folded) || PLACE_BEFORE.contains(&folded))
            {
                continue;
            }
        }
        // The first mark after it, from the text itself: a masked value's
        // stand-in in the residue view is no clause end, so a mask never makes
        // the possessive before it stand alone.
        let next = words.get(index + 2);
        let tail = next.map_or(&text[s.end..], |next| &text[s.end..next.start]);
        let alone = match tail.chars().find(|&ch| ch == '\n' || !ch.is_whitespace()) {
            Some(ch) => matches!(ch, ',' | ')') || is_sentence_end(ch),
            None => next.is_none_or(|next| AFTER_ALONE.contains(&next.folded.as_str())),
        };
        if alone {
            out.push(health(word.start, s.end, false, "en"));
        }
    }
}

/// Han disease words that end a disease name, with the anchor each one asks
/// for: 晨雾热 is a fever word and needs a health anchor in its sentence
/// (天气热 is the weather), 灰羽病, 晨雾症 and 综合征 are disease words and do
/// not.
const HAN_DISEASE_ENDS: &[(char, bool)] =
    &[('热', true), ('病', false), ('症', false), ('征', false)];

/// Han characters that never start a two-character disease name: degree words,
/// verbs and particles (很热, 生病, 看病, 毛病).
const HAN_NOT_A_NAME: &[char] = &[
    '很', '太', '真', '好', '挺', '更', '最', '超', '不', '怪', '蛮', '较', '特', '发', '生', '看',
    '得', '患', '有', '的', '了', '在', '做', '是', '和', '与', '毛', '气', '天',
];

/// Han characters that may follow a disease name: particles and conjunctions.
const HAN_AFTER_NAME: &[char] = &['的', '了', '和', '与', '及', '等', '请', '复', '已', '又'];

/// Push the two-character Han names a disease word ends (晨雾热). A `病`, `症` or
/// `综合征` hit stands on its own; a `热` hit stands only when a health term or
/// cue shares its sentence.
fn push_han_disease_names(view: &HanView, text: &str, out: &mut Vec<Hit>) {
    let chars: Vec<(usize, char)> = view.text.char_indices().collect();
    for at in 2..chars.len() {
        let (end_at, end) = chars[at];
        let Some(&(_, contextual)) = HAN_DISEASE_ENDS.iter().find(|(ch, _)| *ch == end) else {
            continue;
        };
        // `综合征` ends in 征, a common word (征收, 应征): it is a disease word
        // only after 综合, and the name is then the three characters.
        let first = if end == '征' {
            (at >= 2 && chars[at - 2].1 == '综' && chars[at - 1].1 == '合').then_some(at - 2)
        } else {
            Some(at - 2)
        };
        let Some(first) = first else { continue };
        let heads = [chars[first].1, chars[first + 1].1];
        if !heads
            .iter()
            .all(|&ch| is_han(ch) && !HAN_NOT_A_NAME.contains(&ch))
        {
            continue;
        }
        let Some((from, to)) = view.original(chars[first].0, end_at + end.len_utf8()) else {
            continue;
        };
        let next = text[to..].chars().next();
        if next.is_some_and(|ch| is_han(ch) && !HAN_AFTER_NAME.contains(&ch)) {
            continue;
        }
        out.push(health(from, to, contextual, "zh"));
    }
}

/// Whether an ambiguous abbreviation is a date: a day or a year sits next to it
/// (`12 SEP 2025`, `SEP 12`), so it is a month, not the disease.
fn dated(text: &str, span: Span) -> bool {
    let is_space = |ch: char| ch == ' ' || ch == '\u{a0}';
    let after = text[span.end..].trim_start_matches(is_space).chars().next();
    let before = text[..span.start]
        .trim_end_matches(is_space)
        .chars()
        .next_back();
    after.is_some_and(|ch| ch.is_ascii_digit()) || before.is_some_and(|ch| ch.is_ascii_digit())
}

/// Push the Han terms found in the view, mapped back to the original text. A
/// match that an exception's suffix follows is skipped.
fn push_han(
    view: &HanView,
    terms: &[(String, EntityKind)],
    except: &[(String, String)],
    out: &mut Vec<Hit>,
) {
    for (term, kind) in terms {
        for (start, matched) in view.text.match_indices(term.as_str()) {
            let end = start + matched.len();
            let excepted = except.iter().any(|(excepted, suffix)| {
                excepted == term && view.text[end..].starts_with(suffix.as_str())
            });
            if excepted {
                continue;
            }
            if let Some((from, to)) = view.original(start, end) {
                out.push(Hit {
                    span: Span::new(*kind, from, to, SCORE, NAME),
                    contextual: false,
                    lang: "zh",
                });
            }
        }
    }
}

/// One compiled lexicon: the terms, or the cues that anchor the ambiguous ones.
struct Lexicon {
    phrases: Vec<Phrase>,
    /// Phrases whose first token is an exact word (or its plural or feminine
    /// form), keyed by that form.
    by_word: HashMap<String, Vec<usize>>,
    /// Phrases whose first token is a stem, keyed by the stem.
    by_stem: HashMap<String, Vec<usize>>,
    /// The longest first-token stem, in bytes: a word's prefix longer than this
    /// cannot be a key, so the prefix scan stops there (keeps it linear).
    longest_stem: usize,
    /// Han terms, matched as substrings.
    han: Vec<(String, EntityKind)>,
    /// Han exceptions: `(term, suffix)` for a line `term|suffix`, a match of
    /// `term` that the suffix follows is not the term (中风险 is not 中风).
    han_except: Vec<(String, String)>,
    /// Single-word terms of four or more letters from the compounding
    /// languages, matched inside a longer word: a compound, or a case ending.
    compounds: Option<(AhoCorasick, Vec<(EntityKind, &'static str)>)>,
}

impl Lexicon {
    fn build(entries: Vec<Entry>) -> Self {
        let mut lexicon = Lexicon {
            phrases: Vec::new(),
            by_word: HashMap::new(),
            by_stem: HashMap::new(),
            longest_stem: 0,
            han: Vec::new(),
            han_except: Vec::new(),
            compounds: None,
        };
        let mut compounds: Vec<(String, EntityKind, &'static str)> = Vec::new();
        // Two spellings that fold to one word (`chimiothérapie` and
        // `chimiotherapie`) index once, so no span is recorded twice.
        let mut seen: HashSet<String> = HashSet::new();
        // The exceptions of the Latin terms, keyed by the row they except.
        let mut excluded: HashMap<(EntityKind, String, String), Vec<String>> = HashMap::new();
        for entry in &entries {
            let Some(list) = &entry.except else { continue };
            if entry.term.chars().any(is_han) {
                lexicon.han_except.push((entry.term.clone(), list.clone()));
            } else {
                excluded.insert(
                    (entry.kind, entry.lang.clone(), entry.term.clone()),
                    list.split(',').map(fold_str).collect(),
                );
            }
        }
        for entry in entries {
            if entry.except.is_some() {
                // An exception row is not a term of its own.
                continue;
            }
            if entry.term.chars().any(is_han) {
                let term = entry.term.trim_end_matches('*').to_string();
                if seen.insert(format!("{}|{term}", entry.kind)) {
                    lexicon.han.push((term, entry.kind));
                }
                continue;
            }
            let exceptions = excluded
                .get(&(entry.kind, entry.lang.clone(), entry.term.clone()))
                .cloned()
                .unwrap_or_default();
            let tokens = tokens_of(&entry.term, &entry.lang, exceptions);
            let Some(first) = tokens.first() else {
                continue;
            };
            // Five letters, not four: a four-letter form (Slovene raka, raku) sits
            // inside ordinary words (poraka, praka). Every repro form is five or more.
            if entry.compound && tokens.len() == 1 && first.text.chars().count() >= 5 {
                compounds.push((first.text.clone(), entry.kind, language(&entry.lang)));
            }
            let key = tokens
                .iter()
                .map(|token| format!("{}{}", token.text, if token.stem { "*" } else { "" }))
                .collect::<Vec<_>>()
                .join(" ");
            if !seen.insert(format!("{}|{}|{key}", entry.kind, entry.lang)) {
                continue;
            }
            let id = lexicon.phrases.len();
            match first.index() {
                Index::Exact(forms) => {
                    for form in forms {
                        lexicon.by_word.entry(form).or_default().push(id);
                    }
                }
                Index::Prefix(stem) => {
                    lexicon.longest_stem = lexicon.longest_stem.max(stem.len());
                    lexicon.by_stem.entry(stem).or_default().push(id);
                }
            }
            lexicon.phrases.push(Phrase {
                kind: entry.kind,
                tokens,
                contextual: entry.contextual,
                lang: language(&entry.lang),
            });
        }
        if !compounds.is_empty() {
            let patterns: Vec<&str> = compounds.iter().map(|(text, _, _)| text.as_str()).collect();
            let kinds = compounds
                .iter()
                .map(|(_, kind, lang)| (*kind, *lang))
                .collect();
            let automaton = AhoCorasick::new(patterns).expect("compound terms build");
            lexicon.compounds = Some((automaton, kinds));
        }
        lexicon
    }

    /// Record each word that holds a compound term. The words are joined with a
    /// separator that no term contains, so one scan finds every compound and a
    /// match always lies inside one word.
    fn push_compounds(&self, words: &[Word], out: &mut Vec<Hit>) {
        let Some((automaton, kinds)) = &self.compounds else {
            return;
        };
        let mut joined = String::new();
        let mut starts = Vec::with_capacity(words.len());
        for word in words {
            starts.push(joined.len());
            joined.push_str(&word.folded);
            joined.push('\u{1}');
        }
        for found in automaton.find_iter(joined.as_str()) {
            let (kind, lang) = kinds[found.pattern().as_usize()];
            let index = starts.partition_point(|&start| start <= found.start()) - 1;
            out.push(Hit {
                span: Span::new(kind, words[index].start, words[index].end, SCORE, NAME),
                contextual: false,
                lang,
            });
        }
    }

    /// Record each word that is a one-word health term of [`MIN_TAGGED`] or more
    /// bytes glued to an ASCII tag of at most [`MAX_TAG`] letters or digits before
    /// and after it (`refchimiothérapie`, `chemotherapyok`), HEALTH-LABEL-1. A
    /// shorter term (`aids` in `raids`, `hiv` in `archive`) never takes a tag. At
    /// most 25 exact lookups per word, and for a stem of [`MIN_TAGGED`] or more
    /// bytes behind a leading tag (`refdiabetic`, `id42depressive`) at most
    /// [`MAX_TAG`] × the longest stem: linear.
    fn push_tagged(&self, words: &[Word], out: &mut Vec<Hit>) {
        let ascii = |b: &u8| b.is_ascii_alphanumeric();
        for word in words {
            let folded = word.folded.as_str();
            if folded.len() <= MIN_TAGGED || folded.len() > MIN_TAGGED + 64 {
                continue;
            }
            let lead = folded.bytes().take_while(ascii).count().min(MAX_TAG);
            let tail = folded.bytes().rev().take_while(ascii).count().min(MAX_TAG);
            let exact = (0..=lead)
                .flat_map(|p| (0..=tail).map(move |s| (p, s)))
                .filter(|&(p, s)| p + s > 0 && p + s + MIN_TAGGED <= folded.len())
                .flat_map(|(p, s)| self.by_word.get(&folded[p..folded.len() - s]))
                .flatten();
            let stems = (1..=lead).flat_map(|p| {
                let rest = &folded[p..];
                rest.char_indices()
                    .map(|(at, ch)| at + ch.len_utf8())
                    .skip_while(|&end| end < MIN_TAGGED)
                    .take_while(|&end| end <= self.longest_stem)
                    .flat_map(move |end| self.by_stem.get(&rest[..end]))
                    .flatten()
                    .filter(move |&&id| self.phrases[id].tokens[0].matches(rest, true))
            });
            let found = exact
                .chain(stems)
                .map(|&id| &self.phrases[id])
                .find(|phrase| {
                    phrase.kind == EntityKind::Health
                        && phrase.tokens.len() == 1
                        && !phrase.contextual
                });
            if let Some(phrase) = found {
                out.push(Hit {
                    span: Span::new(phrase.kind, word.start, word.end, SCORE, NAME),
                    contextual: false,
                    lang: phrase.lang,
                });
            }
        }
    }

    /// Record every phrase that starts at word `index`.
    fn match_at(&self, text: &str, words: &[Word], index: usize, out: &mut Vec<Hit>) {
        let word = words[index].folded.as_str();
        if let Some(ids) = self.by_word.get(word) {
            for &id in ids {
                self.phrase_at(id, text, words, index, out);
            }
        }
        let prefixes = word
            .char_indices()
            .map(|(at, ch)| at + ch.len_utf8())
            .take_while(|&end| end <= self.longest_stem);
        for end in prefixes {
            if let Some(ids) = self.by_stem.get(&word[..end]) {
                for &id in ids {
                    self.phrase_at(id, text, words, index, out);
                }
            }
        }
    }

    /// Record phrase `id` if its remaining tokens match the words after `index`.
    fn phrase_at(&self, id: usize, text: &str, words: &[Word], index: usize, out: &mut Vec<Hit>) {
        let phrase = &self.phrases[id];
        let last = index + phrase.tokens.len() - 1;
        if last >= words.len() {
            return;
        }
        for (offset, token) in phrase.tokens.iter().enumerate() {
            let word = &words[index + offset];
            if !token.matches(&word.folded, offset + 1 == phrase.tokens.len()) {
                return;
            }
            if offset > 0 && !joins(text, words[index + offset - 1].end, word.start) {
                return;
            }
        }
        out.push(Hit {
            span: Span::new(
                phrase.kind,
                words[index].start,
                words[last].end,
                SCORE,
                NAME,
            ),
            contextual: phrase.contextual,
            lang: phrase.lang,
        });
    }
}

/// One parsed lexicon line.
struct Entry {
    kind: EntityKind,
    lang: String,
    term: String,
    /// A `?` term: an ambiguous abbreviation, kept only next to a health anchor.
    contextual: bool,
    /// A `HEALTHCUE` line: a health cue, not a term.
    cue: bool,
    /// A term of a compounding language (Hungarian, Afrikaans, Slovene), which
    /// also matches inside a longer word.
    compound: bool,
    /// For an exception line `term|list`: the exceptions of that term. A Han
    /// term lists the suffix that must not follow it (`中风|险`: 中风险 is not
    /// 中风); a Latin term lists the words it must not match, comma-separated
    /// (`FIV|five,fives`: `FIV` is `FIV`, never `five`).
    except: Option<String>,
}

/// Parse a lexicon line. Comments, blank lines and malformed lines give `None`.
fn parse_line(line: &str) -> Option<Entry> {
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split('\t');
    let category = fields.next()?;
    let lang = fields.next()?;
    let term = fields.next()?.trim();
    if fields.next().is_some() || term.is_empty() {
        return None;
    }
    if !matches!(lang, "fr" | "en" | "af" | "hu" | "sl" | "zh" | "xx") {
        return None;
    }
    let (kind, cue) = if category == "HEALTHCUE" {
        (EntityKind::Health, true)
    } else {
        let kind = EntityKind::parse(category).filter(|kind| {
            matches!(
                kind,
                EntityKind::Health
                    | EntityKind::Religion
                    | EntityKind::SexualOrientation
                    | EntityKind::Union
                    | EntityKind::Ethnicity
            )
        })?;
        (kind, false)
    };
    let (term, contextual) = match term.strip_prefix('?') {
        Some(rest) => (rest, true),
        None => (term, false),
    };
    if contextual && (cue || kind != EntityKind::Health) || term.is_empty() {
        return None;
    }
    let (term, except) = match term.split_once('|') {
        Some((term, suffix)) if !term.is_empty() && !suffix.is_empty() && !cue => {
            (term, Some(suffix.to_string()))
        }
        Some(_) => return None,
        None => (term, None),
    };
    Some(Entry {
        kind,
        lang: lang.to_string(),
        term: term.to_string(),
        contextual,
        cue,
        compound: matches!(lang, "hu" | "af" | "sl") && !cue && !contextual,
        except,
    })
}

/// The words of a Latin term. A trailing `*` makes a stem; an empty word is
/// dropped. `excluded` are the words the row must not match.
fn tokens_of(term: &str, lang: &str, excluded: Vec<String>) -> Vec<Token> {
    let inflection = match lang {
        "sl" => Inflection::Slovene,
        "hu" => Inflection::Hungarian,
        "en" => Inflection::English,
        "xx" => Inflection::Name,
        _ => Inflection::Plain,
    };
    term.split([' ', '-', '\'', '\u{2019}', '\u{02BC}'])
        .filter_map(|part| {
            let (text, stem) = match part.strip_suffix('*') {
                Some(body) => (body, true),
                None => (part, false),
            };
            let text = fold_str(text);
            (!text.is_empty()).then_some(Token {
                text,
                stem,
                inflection,
                excluded: excluded.clone(),
            })
        })
        .collect()
}

/// The two lexicons, compiled once: the terms, and the health cues.
struct Lexicons {
    terms: Lexicon,
    cues: Lexicon,
}

/// The lexicons, compiled once.
fn lexicons() -> &'static Lexicons {
    static LEXICONS: OnceLock<Lexicons> = OnceLock::new();
    LEXICONS.get_or_init(|| {
        let (cues, terms): (Vec<Entry>, Vec<Entry>) = DATA
            .lines()
            .filter_map(parse_line)
            .partition(|entry| entry.cue);
        Lexicons {
            terms: Lexicon::build(terms),
            cues: Lexicon::build(cues),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        SensitiveTermsRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn every_lexicon_line_is_well_formed() {
        for (number, line) in DATA.lines().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            assert!(
                parse_line(line).is_some(),
                "lexicon line {} is malformed",
                number + 1
            );
        }
    }

    #[test]
    fn case_and_accents_fold_to_one_word() {
        assert_eq!(hits("CHIMIOTHÉRAPIE"), vec!["CHIMIOTHÉRAPIE"]);
        assert_eq!(hits("chimiotherapie"), vec!["chimiotherapie"]);
        assert_eq!(hits("Cancers"), vec!["Cancers"]);
    }

    #[test]
    fn a_term_is_a_whole_word() {
        assert!(hits("The cancelled flight").is_empty());
        assert!(hits("Rakete").is_empty());
    }

    #[test]
    fn a_stem_matches_every_inflection() {
        assert_eq!(hits("cukorbetegségben"), vec!["cukorbetegségben"]);
        assert_eq!(hits("sladkorna"), vec!["sladkorna"]);
    }

    #[test]
    fn an_english_final_word_takes_the_y_ies_and_verb_forms() {
        assert_eq!(hits("pregnancies"), vec!["pregnancies"]);
        assert_eq!(hits("disabilities"), vec!["disabilities"]);
        assert_eq!(hits("chemotherapies"), vec!["chemotherapies"]);
        assert_eq!(hits("miscarried"), vec!["miscarried"]);
        assert_eq!(hits("hospitalized"), vec!["hospitalized"]);
        assert_eq!(hits("hospitalised"), vec!["hospitalised"]);
        assert_eq!(hits("hospitalization"), vec!["hospitalization"]);
        assert_eq!(hits("two hospitalizations"), vec!["hospitalizations"]);
        assert_eq!(hits("a kidney stone"), vec!["kidney stone"]);
        assert_eq!(hits("one gallstone"), vec!["gallstone"]);
        assert_eq!(hits("a varicose vein"), vec!["varicose vein"]);
        assert_eq!(hits("kidney stones"), vec!["kidney stones"]);
        assert_eq!(hits("disabled"), vec!["disabled"]);
        assert_eq!(hits("addicted"), vec!["addicted"]);
        assert_eq!(hits("overdosed"), vec!["overdosed"]);
        assert_eq!(hits("overdoses"), vec!["overdoses"]);
        assert_eq!(hits("seizures"), vec!["seizures"]);
        assert_eq!(hits("heroin"), vec!["heroin"]);
        assert_eq!(hits("methadone"), vec!["methadone"]);
    }

    #[test]
    fn a_multi_word_term_joins_across_hyphens_and_spaces() {
        assert_eq!(hits("self-harm"), vec!["self-harm"]);
        assert_eq!(hits("sick  leave"), vec!["sick  leave"]);
        assert!(hits("sick, leave").is_empty());
    }

    #[test]
    fn an_apostrophe_ends_a_word() {
        assert_eq!(hits("l'insomnie"), vec!["insomnie"]);
    }

    #[test]
    fn the_han_fold_table_is_sorted_and_keeps_byte_offsets() {
        let pairs = han_fold_pairs();
        assert!(!pairs.is_empty());
        assert!(pairs.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for &(traditional, simplified) in pairs {
            assert_eq!(traditional.len_utf8(), 3);
            assert_eq!(simplified.len_utf8(), 3);
        }
        assert_eq!(HanView::new("憂鬱症").text, "忧郁症");
    }

    #[test]
    fn a_han_term_matches_inside_a_run_of_characters() {
        assert_eq!(hits("他的糖尿病复发了。"), vec!["糖尿病"]);
    }

    #[test]
    fn a_combining_mark_and_an_invisible_character_stay_inside_the_word() {
        // `e` plus U+0301 is the same word as the precomposed `é`.
        assert_eq!(
            hits("chimiothe\u{0301}rapie"),
            vec!["chimiothe\u{0301}rapie"]
        );
        assert_eq!(hits("can\u{200B}cer"), vec!["can\u{200B}cer"]);
    }

    /// The common words the capitals rows inflect to, and the exception that
    /// takes each of them away (`FIV` is `FIV`, never `five`).
    const EXCEPTED: &[&str] = &["five", "fives", "hive", "hived", "hiving"];

    /// Whether a term is a capitals row of at most five letters: an abbreviation.
    fn is_abbreviation(term: &str) -> bool {
        !term.is_empty() && term.len() <= 5 && term.bytes().all(|byte| byte.is_ascii_uppercase())
    }

    /// The health cue that makes a sentence a health sentence in each language.
    fn cue(lang: &str) -> &'static str {
        match lang {
            "af" => "pasiënt",
            "hu" => "beteg",
            "sl" => "bolnik",
            _ => "patient",
        }
    }

    /// K-OVERMASK-FIVE: every abbreviation of the lexicon masks its own word, in
    /// any case.
    #[test]
    fn an_abbreviation_masks_its_own_word_in_any_case() {
        for entry in DATA.lines().filter_map(parse_line) {
            if entry.cue || entry.except.is_some() || !is_abbreviation(&entry.term) {
                continue;
            }
            let mut chars = entry.term.chars();
            for spelling in [
                entry.term.clone(),
                entry.term.to_lowercase(),
                chars
                    .next()
                    .map(|first| first.to_string() + chars.as_str())
                    .unwrap_or_default(),
            ] {
                let text = format!("{}: {spelling}.", cue(&entry.lang));
                assert!(
                    hits(&text).contains(&spelling),
                    "{spelling} ({}) left in clear: {text}",
                    entry.term
                );
            }
        }
    }

    /// K-OVERMASK-FIVE: the probe. The inflected forms of the capitals rows, the
    /// ones a word list holds: each of them is either excepted by its row or
    /// still masked by the lexicon (`hives` is urticaria, and health fails
    /// closed).
    #[test]
    fn a_capitals_row_excepts_the_common_words_it_infects_to() {
        let words: Vec<String> = std::fs::read_to_string("/usr/share/dict/words")
            .map(|text| {
                text.lines()
                    .map(|line| line.trim().to_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        let mut collisions: HashSet<String> = HashSet::new();
        for entry in DATA.lines().filter_map(parse_line) {
            if entry.cue || entry.except.is_some() || !is_abbreviation(&entry.term) {
                continue;
            }
            let base = fold_str(&entry.term);
            let legacy = Token {
                text: base.clone(),
                stem: false,
                inflection: match entry.lang.as_str() {
                    "sl" => Inflection::Slovene,
                    "hu" => Inflection::Hungarian,
                    "en" => Inflection::English,
                    _ => Inflection::Plain,
                },
                excluded: Vec::new(),
            };
            // Every word of the list the row's stem takes: the forms the row
            // inflects to are the words it matches.
            let stem = match entry.lang.as_str() {
                "sl" => slovene_stem(&base).to_string(),
                "hu" => hungarian_stem(&base).to_string(),
                _ => base.clone(),
            };
            for word in words.iter().filter(|w| w.starts_with(&stem) && *w != &base) {
                if legacy.matches(word, true) {
                    collisions.insert(word.clone());
                }
            }
        }
        for word in &collisions {
            if hits(word).is_empty() {
                assert!(
                    EXCEPTED.contains(&word.as_str()),
                    "a new common word is masked: {word}"
                );
            }
        }
    }
}
