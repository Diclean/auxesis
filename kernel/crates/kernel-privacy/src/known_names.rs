//! A caller-supplied dictionary of known person names: the Tier H half of
//! Standard detection (D7).
//!
//! The dictionary is local and exhaustive for the names it is given. For each
//! entry it compiles the surface forms a person is actually written under —
//! full name in either order, given or family name alone, initials, titles,
//! concatenations, possessives and elisions — and matches each one as a whole
//! word, case-, accent- and separator-insensitively. The caller seeds it from
//! the owner's contacts index (or any list the owner chose); it never leaves
//! the machine.
//!
//! Matching is script aware. A name written in a script without spaces (Han,
//! Hiragana, Katakana, Hangul, Thai, Lao, Khmer, Myanmar) matches as a
//! substring, and a character from such a script is a word boundary for every
//! other script. A caseless script has no "capitalised" notion, so its parts
//! are always eligible.
//!
//! A spaced-script part `P` (folded, `n` letters) also matches an inflected
//! word `W` by one of two rules:
//!
//! - a tail: `W` starts with `P` and the rest is one to six letters of the same
//!   script (`Tomin`, `Leolle`, `ரவிக்கு`), for `n ≥ 3`;
//! - a stem: `W` starts with the first `max(3, n−2)` letters of `P`, is between
//!   `n−1` and `n+6` letters long, and changes the ending (`Pekka` → `Pekan`,
//!   Finnish `Virtanen` → `Virtasen` through its own form). For `n == 3` in a
//!   cased script the stem is two letters and `W` is `n` to `n+3` letters.
//!
//! In a cased script a tail or stem must be capitalised, all upper case, or
//! follow a title, so a lower-case word never matches by inflection. A stem is
//! never a match on its own. Attached Hebrew and Arabic prefixes are compiled
//! too, and the Arabic, diacritic-transliteration and Latin-homoglyph folds are
//! symmetric between the entry and the text. A Cyrillic or Greek look-alike folds
//! to Latin only inside a Latin word (`Cаmille`); every other word keeps its
//! letters. A one-part entry with a diacritic (`Bäck`) keeps its own spelling; a
//! spelling its strip or transliteration derives needs a capital.
//!
//! Mounting the recogniser in a [`crate::Registry`] adds its `PERSON` spans to
//! the deterministic pipeline, where the e-mail layer propagates them and the
//! anonymizer masks them like any other value.

use std::collections::BTreeMap;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::contacts::fold::{
    fold_homoglyphs, fold_homoglyphs_plain, fold_separators, fold_separators_homoglyphs,
    fold_separators_homoglyphs_plain, is_indic_sign, is_latin_diacritic, is_no_space_script,
    Folded,
};
use crate::contacts::{inflect, stopwords};
use crate::recognizer::Recognizer;
use crate::recognizers::email::EmailRecognizer;
use crate::span::{EntityKind, Span};

/// The stable recogniser name echoed in [`Span::recognizer`].
pub const KNOWN_NAMES: &str = "known_names";

/// Titles that release a two-letter part or a particle from the case rule.
const TITLES: &[&str] = &[
    "m",
    "mme",
    "mlle",
    "mr",
    "mrs",
    "ms",
    "dr",
    "pr",
    "prof",
    "monsieur",
    "madame",
    "mademoiselle",
    "maitre",
    "herr",
    "frau",
    "sr",
    "sra",
];

/// Particles that name nobody on their own: they match only after a title, and
/// are included when they sit inside a longer matched run.
const PARTICLES: &[&str] = &[
    "de", "du", "des", "der", "den", "van", "von", "di", "da", "dos", "das", "del", "della", "le",
    "la", "les", "el", "al", "bin", "ibn", "ben", "ter", "ten", "het", "zu", "op", "ap", "abu",
    "o", "d",
];

/// The Hebrew letters that attach to a name part as a prefix.
const HEBREW_PREFIXES: &[&str] = &["ו", "ה", "ב", "כ", "ל", "מ", "ש"];

/// The Arabic compound openers whose spaced and glued spellings both name the
/// same person (`عبد الله` / `عبدالله`).
const ARABIC_COMPOUNDS: &[&str] = &["عبد", "ابو", "ابن"];

/// Why a known-names dictionary could not be compiled. The dictionary never
/// degrades to matching nothing: a caller that gets this error mounts no
/// dictionary, and a private gate then fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NameDictionaryError {
    /// The Aho-Corasick automaton rejected the compiled patterns.
    #[error("the known-names automaton could not be compiled")]
    Build,
}

/// How much evidence a compiled surface form carries.
///
/// Ordered from weakest to strongest, so merging two entries for the same
/// pattern keeps the most permissive check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NameCheck {
    /// Only after a title (`Mme Le`).
    Titled,
    /// Capitalised, all-caps, or after a title (`Wu`).
    Short,
    /// Any casing (`Camille`, `camille exemple`).
    Any,
}

impl NameCheck {
    /// The check a token carries when it stands alone. A caseless script has
    /// no capitalisation to require, so its parts are always eligible. A short
    /// part, and a part that is also a common word (`will`, `may`, `rose`),
    /// needs a capital: the lower-case word is the common one.
    fn for_token(token: &str) -> Self {
        if is_caseless(token) {
            Self::Any
        } else if letters(token) == 2 || stopwords::is_common_word(token) {
            Self::Short
        } else {
            Self::Any
        }
    }

    /// Whether a match at `text[start..end]`, whose folded form begins at
    /// `begin`, satisfies this check.
    fn passes(self, text: &str, start: usize, end: usize, folded: &str, begin: usize) -> bool {
        match self {
            Self::Any => true,
            Self::Short => is_capitalised(&text[start..end]) || preceded_by_title(folded, begin),
            Self::Titled => preceded_by_title(folded, begin),
        }
    }
}

/// How one compiled pattern may match.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PatternRule {
    /// The evidence the matched text must carry.
    check: NameCheck,
    /// The own spelling of each one-part entry with a diacritic that compiles to
    /// this pattern, with that entry's check. A match written in one of these
    /// spellings keeps the entry's rule; any other spelling is derived from it
    /// and needs `check`.
    spelled: Vec<(String, NameCheck)>,
    /// The case-kept spelling of each one-part entry written in lower case. A
    /// text word spelled exactly so is that entry, so it matches whatever the
    /// common-word rule says: `rose` for a contact stored as `rose`.
    cased: Vec<String>,
    /// A no-space-script pattern matches as a substring, with no boundary.
    no_space: bool,
    /// The pattern is a name form, so it matches a whole word on its own. A
    /// stem is not: it matches only a longer word through its [`StemRange`].
    exact: bool,
    /// A whole spaced-script name part of three letters or more accepts a tail
    /// of one to six letters of the same script.
    tail: bool,
    /// A stem accepts a whole word whose letter count is in this range.
    stem: Option<StemRange>,
}

/// The letter counts a stem may stand for: the whole word, from `min` to `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StemRange {
    min: usize,
    max: usize,
}

impl PatternRule {
    fn for_pattern(pattern: &str, check: NameCheck) -> Self {
        Self {
            check,
            spelled: Vec::new(),
            cased: Vec::new(),
            no_space: pattern.chars().any(is_no_space_script),
            exact: true,
            tail: false,
            stem: None,
        }
    }

    /// The check for a match whose source text is `source`.
    fn check_for(&self, source: &str) -> NameCheck {
        if !self.cased.is_empty() && self.cased.contains(&cased_of(source)) {
            return NameCheck::Any;
        }
        if self.spelled.is_empty() {
            return self.check;
        }
        let spelling = spelling_of(source);
        match self.spelled.iter().find(|(own, _)| *own == spelling) {
            Some((_, own)) => self.check.max(*own),
            None => self.check,
        }
    }

    /// Keep the most permissive of two rules for the same pattern.
    fn merge(&self, other: &Self) -> Self {
        let mut spelled = self.spelled.clone();
        for entry in &other.spelled {
            if !spelled.contains(entry) {
                spelled.push(entry.clone());
            }
        }
        let mut cased = self.cased.clone();
        for spelling in &other.cased {
            if !cased.contains(spelling) {
                cased.push(spelling.clone());
            }
        }
        Self {
            check: self.check.max(other.check),
            spelled,
            cased,
            no_space: self.no_space || other.no_space,
            exact: self.exact || other.exact,
            tail: self.tail || other.tail,
            stem: match (self.stem, other.stem) {
                (Some(a), Some(b)) => Some(StemRange {
                    min: a.min.min(b.min),
                    max: a.max.max(b.max),
                }),
                (a, b) => a.or(b),
            },
        }
    }
}

/// The names one caller knows, compiled once for linear matching.
pub struct NameDictionary {
    /// One folded pattern per surface form, matched whole-word.
    names: Option<AhoCorasick>,
    /// The rule for each pattern, indexed by Aho-Corasick pattern id.
    rules: Vec<PatternRule>,
    count: usize,
}

impl NameDictionary {
    /// Compile every surface form of every entry. Blank entries and repeats
    /// are dropped; a form with no letter pair to anchor it is never compiled.
    pub fn new<I, S>(names: I) -> Result<Self, NameDictionaryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut patterns: BTreeMap<String, PatternRule> = BTreeMap::new();
        for name in names {
            for (variant, rule) in variants_for(name.as_ref()) {
                patterns
                    .entry(variant)
                    .and_modify(|current| *current = current.merge(&rule))
                    .or_insert(rule);
            }
        }
        let (patterns, rules): (Vec<String>, Vec<PatternRule>) = patterns.into_iter().unzip();
        Self::compile(patterns, rules)
    }

    /// Compile the folded patterns. An empty pattern is a build error, never a
    /// silently empty dictionary.
    fn compile(
        patterns: Vec<String>,
        rules: Vec<PatternRule>,
    ) -> Result<Self, NameDictionaryError> {
        debug_assert_eq!(patterns.len(), rules.len());
        if patterns.iter().any(String::is_empty) {
            return Err(NameDictionaryError::Build);
        }
        if patterns.is_empty() {
            return Ok(Self {
                names: None,
                rules: Vec::new(),
                count: 0,
            });
        }
        let names = AhoCorasick::new(patterns.iter().map(String::as_str))
            .map_err(|_| NameDictionaryError::Build)?;
        Ok(Self {
            names: Some(names),
            rules,
            count: patterns.len(),
        })
    }

    /// How many distinct surface forms are compiled.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the dictionary holds no usable name.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Match on one folded view and append every surviving span.
    fn scan(&self, folded: &Folded, text: &str, emails: &[Span], spans: &mut Vec<Span>) {
        let Some(automaton) = &self.names else {
            return;
        };
        let folded_text = folded.text();
        for found in automaton.find_overlapping_iter(folded_text) {
            let rule = &self.rules[found.pattern().as_usize()];
            let (begin, mut stop) = (found.start(), found.end());
            let mut extended = false;
            if !rule.no_space {
                if !is_spaced_boundary(folded_text[..begin].chars().next_back()) {
                    continue;
                }
                match spaced_stop(folded, text, begin, stop, rule) {
                    Some((end, runs_on)) => (stop, extended) = (end, runs_on),
                    None => continue,
                }
            }
            let (start, end) = folded.source(begin, stop);
            // An inflected form in a cased script is capitalised, all upper case,
            // or after a title: a lower-case tail or stem is some other word.
            let word = &text[start..end];
            if extended
                && !is_caseless(word)
                && !is_capitalised(word)
                && !preceded_by_title(folded_text, begin)
            {
                continue;
            }
            // A comma is a list separator that folding reads as a space: a
            // match that spans one would fuse two names into one region.
            if text[start..end].contains(',') {
                continue;
            }
            // A name may be part of an address (a match wholly inside it), but
            // a match that starts in the display name and ends inside the
            // address must not bridge the two: the address keeps its own
            // region, and the display name its own token.
            if emails.iter().any(|email| {
                start < email.end && end > email.start && (start < email.start || end > email.end)
            }) {
                continue;
            }
            if !rule
                .check_for(word)
                .passes(text, start, end, folded_text, begin)
            {
                continue;
            }
            spans.push(Span::new(EntityKind::Person, start, end, 1.0, KNOWN_NAMES));
        }
    }
}

/// A compiled dictionary shared by several detectors: each gate mounts a
/// handle to the same automaton, never a fresh compile.
impl Recognizer for Arc<NameDictionary> {
    fn kinds(&self) -> &[EntityKind] {
        (**self).kinds()
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        (**self).analyze(text)
    }

    fn name(&self) -> &'static str {
        KNOWN_NAMES
    }
}

impl Recognizer for NameDictionary {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Person]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        if self.names.is_none() {
            return Vec::new();
        }
        let emails = EmailRecognizer::new().analyze(text);
        let mut spans = Vec::new();
        // The separator view finds a name split by a hidden character; the
        // deletion view finds the same name written without it. Each view is
        // read twice, with `Müller` as `mueller` and as `muller`, so a name
        // typed with or without its diacritics matches. Both map back to the
        // original bytes, and the union is masked.
        for (transliterated, plain) in [
            (
                fold_separators_homoglyphs(text),
                fold_separators_homoglyphs_plain(text),
            ),
            (fold_homoglyphs(text), fold_homoglyphs_plain(text)),
        ] {
            self.scan(&transliterated, text, &emails, &mut spans);
            if plain.text() != transliterated.text() {
                self.scan(&plain, text, &emails, &mut spans);
            }
        }
        spans.sort_by_key(|span| (span.start, span.end));
        spans.dedup_by_key(|span| (span.start, span.end));
        spans
    }

    fn name(&self) -> &'static str {
        KNOWN_NAMES
    }
}

/// Record `pattern` with `check`, keeping the most permissive rule when the
/// same pattern arrives twice.
fn add(out: &mut BTreeMap<String, PatternRule>, pattern: String, check: NameCheck) {
    let rule = PatternRule::for_pattern(&pattern, check);
    add_rule(out, pattern, rule);
}

/// Record `pattern` with `rule`, keeping the most permissive rule when the same
/// pattern arrives twice. A pattern with fewer than two letters is never kept.
fn add_rule(out: &mut BTreeMap<String, PatternRule>, pattern: String, rule: PatternRule) {
    if letters(&pattern) < 2 {
        return;
    }
    out.entry(pattern)
        .and_modify(|current| *current = current.merge(&rule))
        .or_insert(rule);
}

/// Add one token as a standalone pattern when it can stand alone, with its
/// inflections, its stem and its attached prefixes. A particle takes none of
/// the inflection rules: it matches as it did before.
fn add_token(out: &mut BTreeMap<String, PatternRule>, token: &str, plain: &str, check: NameCheck) {
    if letters(token) < 2 {
        return;
    }
    let inflects = !is_particle(token);
    let rule = PatternRule {
        tail: inflects && !token.chars().any(is_no_space_script) && letters(token) >= 3,
        ..PatternRule::for_pattern(token, check)
    };
    add_rule(out, token.to_string(), rule);
    if token.chars().any(is_no_space_script) {
        return;
    }
    for title in TITLES {
        add(out, format!("{title} {token}"), NameCheck::Any);
    }
    for form in inflections(plain) {
        add(
            out,
            fold_separators_homoglyphs(&form).text().to_string(),
            check,
        );
    }
    if inflects {
        if let Some((stem, range)) = stem_of(token) {
            let rule = PatternRule {
                exact: false,
                stem: Some(range),
                ..PatternRule::for_pattern(&stem, check)
            };
            add_rule(out, stem, rule);
        }
    }
    add_attached_prefixes(out, token, check);
}

/// The stem of one spaced name part and the letter count of the whole word it
/// may match. The stem is the first `max(3, n−2)` letters of the part, for a
/// part of four letters or more; a cased part of three letters has a two-letter
/// stem that only matches a word of three to six letters (`Ewa` → `Ewy`). A
/// caseless part of three letters has no stem.
fn stem_of(token: &str) -> Option<(String, StemRange)> {
    let count = letters(token);
    let (keep, min, max) = if count >= 4 {
        (count.saturating_sub(2).max(3), count - 1, count + 6)
    } else if count == 3 && !is_caseless(token) {
        (2, count, count + 3)
    } else {
        return None;
    };
    Some((leading_letters(token, keep), StemRange { min, max }))
}

/// The first `count` letters of `token`, with the marks that follow each one.
fn leading_letters(token: &str, count: usize) -> String {
    let mut out = String::new();
    let mut taken = 0;
    for ch in token.chars() {
        if is_letter_or_mark(ch) {
            if taken == count {
                break;
            }
            taken += 1;
        }
        out.push(ch);
    }
    out
}

/// The short inflections of one name part: the English, French and German
/// suffixes the brief lists, plus the Slavic case endings from
/// [`crate::contacts::inflect`] and the Finnish genitive of `-nen` names
/// (`Virtanen` → `Virtasen`).
fn inflections(token: &str) -> Vec<String> {
    let mut forms = vec![
        format!("{token}s"),
        format!("{token}es"),
        format!("{token} s"),
        format!("{token}x"),
        format!("{token}n"),
        format!("{token}en"),
        format!("{token}ns"),
        format!("{token}em"),
    ];
    if let Some(stem) = token.strip_suffix("nen") {
        forms.push(format!("{stem}sen"));
    }
    forms.extend(inflect::word_forms(token, inflect::Role::Family));
    forms.extend(inflect::word_forms(token, inflect::Role::Given));
    forms
}

/// Compile the attached Hebrew prefixes of one name part. The Arabic prefixes
/// come from [`crate::contacts::inflect`] instead.
fn add_attached_prefixes(out: &mut BTreeMap<String, PatternRule>, token: &str, check: NameCheck) {
    if script_family(token.chars().next().unwrap_or(' ')) != Script::Hebrew {
        return;
    }
    for first in HEBREW_PREFIXES {
        add(out, format!("{first}{token}"), check);
        for second in HEBREW_PREFIXES {
            add(out, format!("{first}{second}{token}"), check);
        }
    }
}

/// Every surface form of one dictionary entry, with its check. The entry is
/// compiled twice, with its diacritics transliterated (`Müller` → `mueller`) and
/// with them stripped (`muller`), so either way of typing it matches.
///
/// The forms cover the ways a person is written: full name in order and
/// reversed, given and family runs alone, an initial with the family name, a
/// given name with an initial, each run concatenated without separators, the
/// possessive of the given name and the elided family name. A particle opens
/// the family run (`Camille Le Gall`, `Sinéad O'Connor`); a no-space script
/// also gets its glued run; an Arabic compound gets both its spellings.
fn variants_for(entry: &str) -> Vec<(String, PatternRule)> {
    // NFC first: an NFD entry is the same spelling as its NFC form.
    let entry: String = entry.nfc().collect();
    let entry = entry.as_str();
    let plain = fold_separators(entry);
    let transliterated = fold_separators_homoglyphs(entry);
    let stripped = fold_separators_homoglyphs_plain(entry);
    let own = entry
        .chars()
        .any(is_latin_diacritic)
        .then(|| spelling_of(entry));
    let cased = (!entry.chars().any(char::is_uppercase)).then(|| cased_of(entry));
    let mut out = variants_from(&transliterated, &plain, own.as_deref(), cased.as_deref());
    if stripped.text() != transliterated.text() {
        for (variant, rule) in variants_from(&stripped, &plain, own.as_deref(), cased.as_deref()) {
            out.entry(variant)
                .and_modify(|current| *current = current.merge(&rule))
                .or_insert(rule);
        }
    }
    out.into_iter().collect()
}

/// The surface forms of `folded`, one entry spelled in one fold. `plain` is the
/// same entry folded without the homoglyph and transliteration maps. `own` is
/// the spelling of an entry with a Latin diacritic, which keeps its own rule
/// only as written: a one-part spelling derived by a strip or a transliteration
/// needs a capital (`back` for `Bäck`). `cased` is the case-kept spelling of a
/// one-part entry written in lower case, which matches as written.
fn variants_from(
    folded: &Folded,
    plain: &Folded,
    own: Option<&str>,
    cased: Option<&str>,
) -> BTreeMap<String, PatternRule> {
    let tokens: Vec<&str> = folded
        .text()
        .split(' ')
        .filter(|token| !token.is_empty())
        .collect();
    let plain_tokens: Vec<&str> = plain
        .text()
        .split(' ')
        .filter(|token| !token.is_empty())
        .collect();
    let mut out: BTreeMap<String, PatternRule> = BTreeMap::new();
    match tokens.as_slice() {
        [] => {}
        [only] => {
            let plain_only = plain_tokens.first().copied().unwrap_or(only);
            match own {
                Some(spelling) => {
                    add_token(&mut out, only, plain_only, NameCheck::Short);
                    let rule = PatternRule {
                        spelled: vec![(spelling.to_string(), NameCheck::for_token(only))],
                        ..PatternRule::for_pattern(only, NameCheck::Short)
                    };
                    add_rule(&mut out, only.to_string(), rule);
                }
                None => add_token(&mut out, only, plain_only, NameCheck::for_token(only)),
            }
            if let Some(spelling) = cased {
                let rule = PatternRule {
                    cased: vec![spelling.to_string()],
                    ..PatternRule::for_pattern(only, NameCheck::Short)
                };
                add_rule(&mut out, only.to_string(), rule);
            }
            for compound in compound_variants(&tokens) {
                add(&mut out, compound, NameCheck::Any);
            }
        }
        _ => {
            let split = family_split(&tokens);
            let given = &tokens[..split];
            let family = &tokens[split..];
            let plain_given = &plain_tokens[..split];
            let plain_family = &plain_tokens[split..];
            let given_phrase = given.join(" ");
            let family_phrase = family.join(" ");
            let given_concat: String = given.concat();
            let family_concat: String = family.concat();

            add(
                &mut out,
                format!("{given_phrase} {family_phrase}"),
                NameCheck::Any,
            );
            add(
                &mut out,
                format!("{family_phrase} {given_phrase}"),
                NameCheck::Any,
            );
            // A multi-part given name alone is a name too (`Дарʼя`, `Jean Pierre`).
            if given.len() >= 2 {
                add(&mut out, given_phrase.clone(), NameCheck::Any);
            }
            // A script without spaces writes the same name glued or spaced.
            if tokens
                .iter()
                .all(|token| token.chars().any(is_no_space_script))
            {
                add(&mut out, tokens.concat(), NameCheck::Any);
            }
            for compound in compound_variants(&tokens) {
                add(&mut out, compound, NameCheck::Any);
            }
            // A particle that is the whole family run names a person
            // (`Camille De`); a particle inside a longer run does not
            // (`Camille Le Gall`).
            let family_check = if family.len() == 1 {
                if is_particle(family[0]) {
                    NameCheck::Short
                } else {
                    NameCheck::for_token(family[0])
                }
            } else {
                NameCheck::Any
            };
            add(&mut out, family_phrase.clone(), family_check);
            // A particle that is the given name is a normal short part
            // (`Ben Martin`, `Van Nguyen`).
            for (token, plain_token) in given.iter().zip(plain_given) {
                let check = if is_particle(token) {
                    NameCheck::Short
                } else {
                    NameCheck::for_token(token)
                };
                add_token(&mut out, token, plain_token, check);
            }
            for (token, plain_token) in family.iter().zip(plain_family) {
                let check = if is_particle(token) {
                    if family.len() == 1 {
                        NameCheck::Short
                    } else {
                        NameCheck::Titled
                    }
                } else {
                    NameCheck::for_token(token)
                };
                add_token(&mut out, token, plain_token, check);
            }
            if let Some(initial) = given.first().and_then(|token| token.chars().next()) {
                add(
                    &mut out,
                    format!("{initial} {family_phrase}"),
                    NameCheck::Any,
                );
            }
            if let Some(initial) = family.first().and_then(|token| token.chars().next()) {
                add(
                    &mut out,
                    format!("{given_phrase} {initial}"),
                    NameCheck::Any,
                );
            }
            if given.len() >= 2 {
                add(&mut out, given_concat.clone(), NameCheck::Any);
                add(
                    &mut out,
                    format!("{given_concat} {family_phrase}"),
                    NameCheck::Any,
                );
            }
            if family.len() >= 2 {
                add(&mut out, family_concat.clone(), NameCheck::Any);
                add(
                    &mut out,
                    format!("{given_phrase} {family_concat}"),
                    NameCheck::Any,
                );
            }
            add(
                &mut out,
                format!("{given_concat}{family_concat}"),
                NameCheck::Any,
            );
            if let Some(first) = given.first() {
                add(&mut out, format!("{first} s"), NameCheck::Any);
            }
            add(&mut out, format!("d {family_phrase}"), NameCheck::Any);
            if family.len() >= 2 {
                add(&mut out, format!("d {family_concat}"), NameCheck::Any);
            }
        }
    }
    out
}

/// The spaced and glued spellings of an Arabic compound (`عبد الله` /
/// `عبدالله`), for the openers in [`ARABIC_COMPOUNDS`].
fn compound_variants(tokens: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    if tokens.len() >= 2 && ARABIC_COMPOUNDS.contains(&tokens[0]) {
        out.push(tokens.concat());
    }
    if tokens.len() == 1 {
        for opener in ARABIC_COMPOUNDS {
            if let Some(rest) = tokens[0].strip_prefix(opener) {
                if !rest.is_empty() {
                    out.push(format!("{opener} {rest}"));
                }
            }
        }
    }
    out
}

/// The index where the family run starts: the first particle after the first
/// token, or the last token when the entry has none.
fn family_split(tokens: &[&str]) -> usize {
    tokens
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, token)| is_particle(token))
        .map(|(index, _)| index)
        .unwrap_or(tokens.len() - 1)
}

/// Whether `token` is a particle that names nobody on its own.
fn is_particle(token: &str) -> bool {
    PARTICLES.contains(&token)
}

/// The script family of `c`, coarse enough to compare a stem and its suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Arabic,
    Hebrew,
    Devanagari,
    NoSpace,
    Other,
}

fn script_family(c: char) -> Script {
    if is_no_space_script(c) {
        return Script::NoSpace;
    }
    match c {
        '\u{0041}'..='\u{024F}' | '\u{1E00}'..='\u{1EFF}' => Script::Latin,
        '\u{0400}'..='\u{052F}' => Script::Cyrillic,
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Script::Greek,
        '\u{0600}'..='\u{06FF}'
        | '\u{0750}'..='\u{077F}'
        | '\u{08A0}'..='\u{08FF}'
        | '\u{FB50}'..='\u{FDFF}'
        | '\u{FE70}'..='\u{FEFF}' => Script::Arabic,
        '\u{0590}'..='\u{05FF}' | '\u{FB1D}'..='\u{FB4F}' => Script::Hebrew,
        '\u{0900}'..='\u{097F}' => Script::Devanagari,
        _ => Script::Other,
    }
}

/// Whether a spaced-script match may start or end here: a text edge, a
/// non-letter, or a character from a script written without spaces.
fn is_spaced_boundary(before: Option<char>) -> bool {
    before.is_none_or(|c| !c.is_alphabetic() || is_no_space_script(c))
}

/// The end of a spaced-script match that starts at `begin` and ends at `stop`,
/// and whether that end runs past the pattern. The match stands as it is when a
/// boundary follows it. Otherwise the word may run on as a tail (one to six
/// letters after the pattern) or as a stem (the whole word, in the stem's
/// letter range), and the run must end at a boundary.
fn spaced_stop(
    folded: &Folded,
    text: &str,
    begin: usize,
    stop: usize,
    rule: &PatternRule,
) -> Option<(usize, bool)> {
    let folded_text = folded.text();
    if rule.exact && is_spaced_boundary(folded_text[stop..].chars().next()) {
        return Some((stop, false));
    }
    let first = folded_text[begin..].chars().next()?;
    let script = source_script(folded, text, begin, first);
    let run = run_end(folded, text, begin, script);
    if run <= stop || !is_spaced_boundary(folded_text[run..].chars().next()) {
        return None;
    }
    let tail = rule.tail && (1..=6).contains(&letters(&folded_text[stop..run]));
    let stem = rule
        .stem
        .is_some_and(|range| (range.min..=range.max).contains(&letters(&folded_text[begin..run])));
    (tail || stem).then_some((run, true))
}

/// The end of the run of letters and marks of `script` that starts at `from`.
/// A character from another script, a no-space character or any other symbol
/// ends the run.
fn run_end(folded: &Folded, text: &str, from: usize, script: Script) -> usize {
    let folded_text = folded.text();
    let mut end = from;
    for ch in folded_text[from..].chars() {
        if !is_letter_or_mark(ch)
            || is_no_space_script(ch)
            || source_script(folded, text, end, ch) != script
        {
            break;
        }
        end += ch.len_utf8();
    }
    end
}

/// The script of the source character behind the folded character `ch` at byte
/// `at` of `folded`.
fn source_script(folded: &Folded, text: &str, at: usize, ch: char) -> Script {
    let (start, _) = folded.source(at, at + ch.len_utf8());
    script_family(text[start..].chars().next().unwrap_or(ch))
}

/// Whether the folded word before `begin` is a title.
fn preceded_by_title(folded: &str, begin: usize) -> bool {
    let before = folded[..begin].trim_end();
    let word = before
        .rsplit(|ch: char| !ch.is_alphabetic())
        .next()
        .unwrap_or("");
    TITLES.contains(&word)
}

/// Whether `value` is capitalised or all upper case.
fn is_capitalised(value: &str) -> bool {
    let letters: Vec<char> = value.chars().filter(|ch| ch.is_alphabetic()).collect();
    match letters.first() {
        Some(first) if first.is_uppercase() => true,
        Some(_) => letters.iter().all(|ch| ch.is_uppercase()),
        None => false,
    }
}

/// The spelling a name is compared by when its diacritics count: NFC and lower
/// case, with the hidden characters and the separators dropped.
fn spelling_of(text: &str) -> String {
    cased_of(text)
        .chars()
        .flat_map(char::to_lowercase)
        .collect()
}

/// The spelling of `text` with its case kept: NFC, with the hidden characters
/// and the separators dropped.
fn cased_of(text: &str) -> String {
    text.nfc()
        .filter(|c| c.is_alphabetic() || is_combining_mark(*c))
        .collect()
}

/// Whether every letter of `token` is caseless (Hebrew, Arabic, CJK, Thai…).
fn is_caseless(token: &str) -> bool {
    let mut any = false;
    for ch in token.chars().filter(|ch| ch.is_alphabetic()) {
        any = true;
        if ch.is_uppercase() || ch.is_lowercase() {
            return false;
        }
    }
    any
}

/// The number of letters in `text`, counting the combining signs of the Indic
/// scripts (see [`is_letter_or_mark`]).
fn letters(text: &str) -> usize {
    text.chars().filter(|ch| is_letter_or_mark(*ch)).count()
}

/// Whether `ch` is a letter, or a combining sign of an Indic script (a vowel
/// sign or a virama). A word's length counts its signs: the Tamil `ரவிக்கு`
/// has seven, and its stem `ரவி` has three.
fn is_letter_or_mark(ch: char) -> bool {
    ch.is_alphabetic() || is_indic_sign(ch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recognizer::resolve_overlaps;

    fn spans(text: &str, names: &[&str]) -> Vec<Span> {
        NameDictionary::new(names)
            .expect("dictionary")
            .analyze(text)
    }

    fn found(text: &str, names: &[&str]) -> bool {
        !spans(text, names).is_empty()
    }

    /// Every probe in `(entry, probes)` must match with that entry.
    fn assert_all(cases: &[(&str, &[&str])]) {
        for (entry, probes) in cases {
            let dictionary = NameDictionary::new([*entry]).expect("dictionary");
            for probe in *probes {
                assert!(
                    !dictionary.analyze(probe).is_empty(),
                    "{probe:?} with {entry:?} matched nothing"
                );
            }
        }
    }

    #[test]
    fn matches_a_multi_token_name_case_insensitively() {
        let found = resolve_overlaps(spans(
            "Bonjour CAMILLE Exemple, ca va ?",
            &["camille exemple"],
        ));
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].start, found[0].end), (8, 23));
        assert_eq!(found[0].kind, EntityKind::Person);
    }

    #[test]
    fn a_partial_word_is_not_a_match() {
        let dictionary = NameDictionary::new(["Camille"]).expect("dictionary");
        assert!(dictionary.analyze("xcamille").is_empty());
        // A lower-case tail is not a capitalised word, so no tail rule matches.
        assert!(dictionary.analyze("camillefoobar").is_empty());
    }

    #[test]
    fn digits_are_word_boundaries() {
        assert!(found("Camille2024 a écrit", &["Camille Exemple"]));
    }

    #[test]
    fn two_letter_parts_and_particles_follow_the_case_rule() {
        for probe in ["Mme Wu a appelé", "Merci Li", "WU called"] {
            assert!(found(probe, &["Li Wu"]), "{probe:?} matched nothing");
        }
        assert!(
            !found("wu called", &["Li Wu"]),
            "lower-case two-letter part matched without a title"
        );
        assert!(found("Mr Ng will call", &["Ng Ah Kow"]));
        assert!(found("Mme Le Gall", &["Camille Le Gall"]));
        assert!(
            !found("Le dossier est prêt", &["Camille Le Gall"]),
            "a particle alone matched"
        );
        let gall = spans("Mme Le Gall", &["Camille Le Gall"]);
        assert!(gall.iter().any(|span| {
            let value = &"Mme Le Gall"[span.start..span.end];
            value.contains("Le Gall")
        }));
    }

    #[test]
    fn short_entries_compile_with_the_right_check() {
        assert!(NameDictionary::new(["A"]).expect("dictionary").is_empty());
        assert!(NameDictionary::new([""]).expect("dictionary").is_empty());
        let bo = NameDictionary::new(["Bo"]).expect("dictionary");
        assert!(!bo.is_empty());
        assert!(bo.analyze("bo").is_empty());
        assert!(!bo.analyze("Bo").is_empty());
        let le = NameDictionary::new(["Le"]).expect("dictionary");
        assert!(!le.is_empty());
        assert!(le.analyze("le dossier").is_empty());
        assert!(!le.analyze("Le dossier").is_empty());
        let gall = NameDictionary::new(["Camille Le Gall"]).expect("dictionary");
        assert!(gall.analyze("Le dossier").is_empty());
        assert!(!gall.analyze("Mme Le Gall").is_empty());
    }

    #[test]
    fn zero_width_inside_a_name_matches() {
        for probe in ["Rapport de Cam\u{AD}ille Exem\u{AD}ple", "Ca\u{200B}mille"] {
            assert!(found(probe, &["Camille Exemple"]), "{probe:?}");
        }
    }

    #[test]
    fn concatenated_runs_match() {
        assert_all(&[
            ("Jean-Pierre Dupont", &["Merci JeanPierre"]),
            ("Camille Le Gall", &["Mme LeGall"]),
            (
                "Marie-Claire de La Fontaine",
                &["Mme DelaFontaine", "Mme DeLaFontaine"],
            ),
            ("Sinéad O'Connor", &["OConnor"]),
        ]);
    }

    #[test]
    fn cyrillic_and_greek_homoglyphs_fold() {
        for probe in ["C\u{430}mille a appelé", "C\u{3B1}mille"] {
            assert!(found(probe, &["Camille"]), "{probe:?}");
        }
    }

    #[test]
    fn non_latin_names_match_in_every_case() {
        assert_all(&[
            (
                "Сергей Иванов",
                &["СЕРГЕЙ ИВАНОВ звонил", "СЕРГЕЙ", "сергей иванов"],
            ),
            ("Иван Петров", &["ИВАН ПЕТРОВ"]),
            (
                "Νίκος Παπαδόπουλος",
                &["ΝΙΚΟΣ ΠΑΠΑΔΟΠΟΥΛΟΣ", "νίκος παπαδόπουλος", "Νικος"],
            ),
            ("Ηλίας Ευαγγέλου", &["ΗΛΙΑΣ ΕΥΑΓΓΕΛΟΥ", "ηλίας ευαγγέλου"]),
        ]);
    }

    #[test]
    fn a_particle_that_is_a_name_part_matches_short() {
        assert_all(&[
            ("Ben Martin", &["Merci Ben, à demain"]),
            ("Al Pacino", &["Al called"]),
            ("Thanh Le", &["Thanh and Le went", "LE called yesterday"]),
            ("Van Nguyen", &["Van will join"]),
            ("Abu Bakr", &["Abu said hi"]),
            ("Camille De", &["De called"]),
        ]);
        assert!(!found("Le dossier est prêt", &["Camille Le Gall"]));
    }

    #[test]
    fn every_default_ignorable_is_zero_width() {
        let dictionary = NameDictionary::new(["Camille Exemple"]).expect("dictionary");
        for filler in [
            '\u{2061}',
            '\u{2064}',
            '\u{206F}',
            '\u{180E}',
            '\u{1D173}',
            '\u{E0001}',
            '\u{115F}',
            '\u{3164}',
        ] {
            let probe = format!("Ca{filler}mille");
            assert!(
                !dictionary.analyze(&probe).is_empty(),
                "U+{:04X} did not fold",
                filler as u32
            );
        }
    }

    #[test]
    fn inflected_forms_of_a_name_part_match() {
        assert_all(&[
            ("John Smith", &["dinner with the Smiths"]),
            ("Anna Schmidt", &["Annas Auto steht hier", "Schmidts Büro"]),
            ("Camille Exemple", &["les Exemples"]),
            ("Иван Петров", &["Петрова", "Петрову"]),
        ]);
    }

    #[test]
    fn no_space_script_names_match_as_substrings() {
        assert_all(&[
            (
                "王伟",
                &[
                    "王伟",
                    "王伟来了",
                    "我和王伟明天去北京",
                    "Call 王伟 tomorrow",
                ],
            ),
            ("李小龙", &["李小龙说你好"]),
            ("田中太郎", &["田中太郎さんが来ました"]),
            ("田中 太郎", &["田中さんが来ました"]),
            ("さくら", &["さくらさんが来た"]),
            ("김민수", &["김민수가 왔어요"]),
            ("김 민수", &["김민수씨가", "민수야 안녕"]),
            ("สมชาย ใจดี", &["คุณสมชายโทรมา"]),
        ]);
    }

    #[test]
    fn a_no_space_script_char_is_a_word_boundary() {
        assert_all(&[(
            "Camille Exemple",
            &[
                "明天和Camille开会",
                "Camilleさんに連絡",
                "Camille씨가 왔어요",
                "ส่งให้Camilleแล้ว",
            ],
        )]);
    }

    #[test]
    fn generic_suffixes_and_stem_loss() {
        assert_all(&[
            ("Νίκος Παπαδόπουλος", &["του Νίκου", "του Παπαδόπουλου"]),
            ("Jan Kowalski", &["u Kowalskiego", "z Kowalskim", "Janem"]),
            ("Anna Nowak", &["z Nowakiem"]),
            ("Petr Novák", &["Novákovi", "paní Nováková"]),
            ("Олена Шевченко", &["Олени"]),
            ("Mikko Virtanen", &["Virtasen"]),
        ]);
    }

    #[test]
    fn attached_hebrew_and_arabic_prefixes() {
        assert_all(&[
            (
                "דוד כהן",
                &[
                    "לדוד",
                    "ודוד כהן הגיעו",
                    "שדוד אמר",
                    "מדוד",
                    "בכהן",
                    "הכהן",
                    "ולדוד",
                ],
            ),
            ("יוסי לוי", &["ליוסי"]),
        ]);
    }

    #[test]
    fn arabic_script_folding() {
        assert_all(&[
            ("محمد علي", &["علی آمد", "محـمد"]),
            ("علي", &["علی"]),
            ("كريم", &["کریم"]),
            ("فاطمة الزهراء", &["فاطمه آمد"]),
            ("عبدالله", &["اتصل عبد الله"]),
        ]);
    }

    #[test]
    fn ascii_transliteration_both_ways() {
        assert_all(&[
            ("Jürgen Müller", &["Juergen Mueller", "Mueller", "JUERGEN"]),
            ("Søren Kierkegård", &["Soeren", "Kierkegaard"]),
            ("Åsa Ångström", &["Aasa Aangstroem"]),
        ]);
    }

    #[test]
    fn every_seal_variant_is_matched() {
        assert_all(&[
            (
                "Camille Exemple",
                &["Bonjour Camille,", "Camille's file", "Camille a appelé"],
            ),
            (
                "Camille Exemple",
                &["Merci Camille", "Mme Exemple a appelé"],
            ),
            ("Camille Exemple", &["C. Exemple", "Camille E."]),
            ("Camille Exemple", &["Exemple Camille", "Exemple, Camille"]),
            (
                "Camille Exemple",
                &["Camille\u{200B}Exemple", "CamilleExemple"],
            ),
            ("Jean-Pierre Dupont", &["JeanPierre Dupont"]),
        ]);
    }

    #[test]
    fn a_build_failure_is_an_error_not_an_empty_dictionary() {
        assert!(matches!(
            NameDictionary::compile(
                vec![String::new()],
                vec![PatternRule::for_pattern("", NameCheck::Any)]
            ),
            Err(NameDictionaryError::Build)
        ));
    }

    #[test]
    fn an_empty_dictionary_matches_nothing() {
        let dictionary = NameDictionary::new(std::iter::empty::<&str>()).expect("dictionary");
        assert!(dictionary.is_empty());
        assert!(dictionary.analyze("camille exemple").is_empty());
    }
}
