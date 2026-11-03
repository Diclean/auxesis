//! A date of birth after its label (OCR-KERNEL-3b).
//!
//! A date is masked as [`EntityKind::DateOfBirth`] only right after a birth
//! label (`Date of birth`, `DOB`, `born on`, `né(e) le`, `date de naissance`),
//! past blanks, at most one line break and `:`, `=`, `-`, `|` or `*`. A bare
//! date and an invoice date stay as main reads them. The date is numeric
//! (`14/03/1987`, `14.03.1987`, `1987-03-14`) or written with a month name in
//! EN or FR, full or short (`14 March 1987`, `March 14, 1987`, `3 mars 1987`,
//! `14 févr. 1987`), with a four- or two-digit year, and it must be a real
//! calendar date: no 31 February, no month 13, no 29 February 1900. Fields may
//! be set apart by a punctuation mark or by blanks (`12 03 1987`), a label may
//! hold repeated blanks (`Date   of birth`), and a value may follow its label
//! directly (`DOB12/03/1987`). Every label is one automaton match followed by a
//! bounded look-ahead: linear.

use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;

use crate::contacts::fold::is_default_ignorable;
use crate::recognizer::Recognizer;
use crate::recognizers::label_value::fold;
use crate::span::{EntityKind, Span};

/// The name echoed in [`Span::recognizer`].
pub(crate) const NAME: &str = "dob_label";

/// Birth labels, folded (lower case, no accents, `-` and `_` as a space).
const LABELS: &[&str] = &[
    "date of birth",
    "birth date",
    "birthdate",
    "dob",
    "d.o.b.",
    "d.o.b",
    "d0b",
    "dateofbirth",
    "ddn",
    "born",
    "born on",
    "date de naissance",
    "ne le",
    "nee le",
    "ne(e) le",
];

/// Labels that are words of prose too: over a `,` or `;` with a blank after it
/// and none before, they link only in quotes or right after a field delimiter,
/// never at a bare line start (`born, 2026-03-12T10:00`); `born,12/03/1987` and
/// `Né le ; 12/03/1987` still link.
const PROSE_LABELS: &[&str] = &["born", "born on", "ne le", "nee le", "ne(e) le"];

/// EN, then FR articles and demonstratives that make a label prose (`the DOB,
/// 12/03/2026 deadline`). No possessive: `Her date of birth, 12 March 1987` is a
/// person's own date and stays hidden.
const DETERMINERS: &[&str] = &[
    "the", "a", "an", "this", "that", "le", "la", "les", "ce", "cette",
];

/// Longest link between a label and its date, in bytes.
const MAX_LINK: usize = 24;
/// The window a date is read in, in bytes.
const DATE_WINDOW: usize = 40;

static LABEL_SET: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(LABELS)
        .expect("birth labels build")
});

/// Month names, lower case: EN full and short, FR full and short (with or
/// without accents; a dot after a short one is read by [`DATE`]).
const MONTHS: &str = "january|february|march|april|may|june|july|august|september|october|\
    november|december|jan|feb|mar|apr|jun|jul|aug|sept|sep|oct|nov|dec|janvier|février|fevrier|\
    mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre|janv|\
    févr|fevr|avr|juil|déc";

/// Numeric dates: day-month-year, year-month-day, and day, month and year with
/// no mark between the last two (`12/031987`). A year-first day may run into
/// an ISO time (`1987-03-12T00:00:00Z`); the `T` is read, then dropped from the date. Fields are set apart by `. / -`
/// (one blank allowed after) or by one or two blanks; a year has four digits or
/// two.
fn numeric_dates() -> String {
    let sep = r"(?: ?[./-] ?| {1,2})";
    let year = r"(?:\d{4}|\d{2})";
    format!(
        r"\d{{1,2}}{sep}\d{{1,2}}{sep}{year}\b|\d{{4}}{sep}\d{{1,2}}{sep}\d{{1,2}}(?:\b|T)|\d{{1,2}}[./-]\d{{2}}\d{{4}}\b"
    )
}

/// A date at the start of the window: numeric, day-month-year, or month-day-year.
static DATE: LazyLock<Regex> = LazyLock::new(|| {
    let year = r"(?:\d{4}|\d{2})";
    let numeric = numeric_dates();
    Regex::new(&format!(
        r"(?i)^(?:{numeric}|\d{{1,2}}(?:st|nd|rd|th|er|º)?\.? (?:{MONTHS})\.?,? {year}\b|(?:{MONTHS})\.? \d{{1,2}}(?:st|nd|rd|th)?,? {year}\b)"
    ))
    .expect("date regex compiles")
});

/// A numeric date at the start of an OCR-read window ([`ocr_digits`]).
static NUMERIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!("^(?:{})", numeric_dates())).expect("numeric date regex compiles")
});

/// The recogniser for a date of birth after its label.
#[derive(Clone, Copy, Debug, Default)]
pub struct DobLabelRecognizer;

impl DobLabelRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for DobLabelRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::DateOfBirth]
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let (folded, map) = squeeze(fold(text));
        let mut spans = Vec::new();
        for hit in LABEL_SET.find_iter(&folded) {
            let before = folded[..hit.start()].chars().next_back();
            let label_end = LABELS[hit.pattern().as_usize()].ends_with('.');
            let after = folded[hit.end()..].chars().next();
            if before.is_some_and(char::is_alphanumeric)
                || !label_end && after.is_some_and(char::is_alphabetic)
                || glued(text, map[hit.start()], map[hit.end()])
            {
                continue;
            }
            let Some((start, spaced)) = link(text, map[hit.end()]) else {
                continue;
            };
            // Over a `,` or `;` with a blank after it, `the DOB, 12/03/2026
            // deadline` and `was born, 12 March 2024` are prose.
            let prose = PROSE_LABELS.contains(&LABELS[hit.pattern().as_usize()]);
            if spaced && !field_start(text, map[hit.start()], prose) {
                continue;
            }
            let window = &text[start..text.floor_char_boundary(start + DATE_WINDOW)];
            let end = DATE
                .find(window)
                .map(|d| d.as_str().trim_end_matches(['T', 't']))
                .filter(|d| calendar_date(d))
                .map(str::len)
                .or_else(|| ocr_date(window));
            // A value glued to its label must end where a date ends: `DOB2 12/03/1987`
            // is no date `2 12/03` with a tail.
            let tail = |end: usize| {
                let mut rest = window[end..].chars();
                matches!(rest.next(), Some('.' | '/' | '-'))
                    && rest.next().is_some_and(|c| c.is_ascii_digit())
            };
            if let Some(end) = end.filter(|&end| start != map[hit.end()] || !tail(end)) {
                spans.push(Span::new(
                    EntityKind::DateOfBirth,
                    start,
                    start + end,
                    1.0,
                    NAME,
                ));
            }
        }
        spans
    }
}

/// `folded` and its byte map with each run of blanks (space, tab, no-break
/// space) read as one space, so a label written with repeated blanks matches.
/// A kept blank maps to the first of its run.
fn squeeze((folded, map): (String, Vec<usize>)) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(folded.len());
    let mut kept = Vec::with_capacity(map.len());
    let mut blank = false;
    for (at, ch) in folded.char_indices() {
        let is_blank = matches!(ch, ' ' | '\t' | '\u{a0}');
        if is_blank && blank {
            continue;
        }
        blank = is_blank;
        if is_blank {
            out.push(' ');
            kept.push(map[at]);
        } else {
            out.push(ch);
            kept.extend_from_slice(&map[at..at + ch.len_utf8()]);
        }
    }
    kept.push(map[folded.len()]);
    (out, kept)
}

/// `window` with the letters OCR reads for a digit (`O`, `o`, `l`, `I`) as that
/// digit: each swap is one ASCII byte for another, so every offset of the result
/// is the same byte of `window`.
fn ocr_digits(window: &str) -> String {
    window
        .chars()
        .map(|ch| match ch {
            'O' | 'o' => '0',
            'l' | 'I' => '1',
            _ => ch,
        })
        .collect()
}

/// The end of a numeric date at the start of `window` once its OCR letters are
/// read as digits (`I2/03/1987`, `12/O3/1987`), when it is a calendar date and
/// OCR did not make it up: the date holds at least four real digits.
fn ocr_date(window: &str) -> Option<usize> {
    let read = ocr_digits(window);
    let date = NUMERIC.find(&read)?;
    let real = window[..date.end()]
        .bytes()
        .filter(u8::is_ascii_digit)
        .count();
    (real >= 4 && calendar_date(date.as_str())).then_some(date.end())
}

/// Whether the label at `start..end` of `text` sits inside an identifier, glued
/// by a run of joiners to a word before it (`Os-born`, `invoice__dob`,
/// `Os‐born`, `invoice\_dob`) or to letters after it (`dob_date`). The fold
/// reads some joiners as a space, so the whole run is read on `text`.
fn glued(text: &str, start: usize, end: usize) -> bool {
    joined(text[..start].chars().rev(), char::is_alphanumeric)
        || joined(text[end..].chars(), char::is_alphabetic)
}

/// Whether `run` opens with one or more joiners (`-`, `_`, `\`, a Unicode
/// hyphen or dash, `−`) and goes on with a `word` character.
fn joined(mut run: impl Iterator<Item = char>, word: fn(char) -> bool) -> bool {
    let joiner = |ch: char| matches!(ch, '-' | '_' | '\\' | '\u{2010}'..='\u{2015}' | '\u{2212}');
    let mut next = run.next();
    if !next.is_some_and(joiner) {
        return false;
    }
    while next.is_some_and(joiner) {
        next = run.next();
    }
    next.is_some_and(word)
}

/// Whether a [`DATE`] match is a calendar date: numeric ([`numeric_date`]) or
/// with a month name, its day within that month of that year (no 31 February,
/// no 29 February 1900).
fn calendar_date(date: &str) -> bool {
    if !date.chars().any(char::is_alphabetic) {
        return numeric_date(date);
    }
    let lower = date.to_lowercase();
    let words: Vec<&str> = lower
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    let lead = |word: &&str| word.bytes().take_while(u8::is_ascii_digit).count();
    // The first number is the day (`1er`, `3rd`), the second the year.
    let mut numbers = words.iter().filter(|w| lead(w) > 0);
    let (day, year) = (numbers.next(), numbers.next());
    let month = words.iter().find_map(|w| month_number(w));
    match (day, month, year) {
        (Some(day), Some(month), Some(year)) if lead(day) <= 2 => {
            let day = day[..lead(day)].parse().unwrap_or(0);
            valid_date(year.parse().unwrap_or(0), month, day)
        }
        _ => false,
    }
}

/// Whether a numeric date (`14/03/1987`, `03/14/1987`, `1987-03-14`,
/// `14.03.87`) is a calendar date, day-month, month-day or year first.
fn numeric_date(date: &str) -> bool {
    let fields: Vec<&str> = date
        .split(['.', '/', '-', ' '])
        .filter(|field| !field.is_empty())
        .collect();
    // `12/031987`: the month and the year with no mark between.
    if let [day, rest] = fields[..] {
        if rest.len() == 6 {
            let (month, year) = rest.split_at(2);
            return numeric_date(&format!("{day}/{month}/{year}"));
        }
    }
    let n: Vec<u32> = fields.iter().filter_map(|f| f.parse().ok()).collect();
    match n[..] {
        [y, m, d] if fields[0].len() == 4 => valid_date(y, m, d),
        [a, b, y] => valid_date(y, b, a) || valid_date(y, a, b),
        _ => false,
    }
}

/// Whether day `d` of month `m` exists in year `y` (Gregorian leap years).
fn valid_date(y: u32, m: u32, d: u32) -> bool {
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    (1..=12).contains(&m) && (1..=days[m as usize - 1]).contains(&d)
}

/// The number of a month name of [`MONTHS`], lower case.
fn month_number(word: &str) -> Option<u32> {
    Some(match word {
        "january" | "jan" | "janvier" | "janv" => 1,
        "february" | "feb" | "février" | "fevrier" | "févr" | "fevr" => 2,
        "march" | "mar" | "mars" => 3,
        "april" | "apr" | "avril" | "avr" => 4,
        "may" | "mai" => 5,
        "june" | "jun" | "juin" => 6,
        "july" | "jul" | "juillet" | "juil" => 7,
        "august" | "aug" | "août" | "aout" => 8,
        "september" | "sept" | "sep" | "septembre" => 9,
        "october" | "oct" | "octobre" => 10,
        "november" | "nov" | "novembre" => 11,
        "december" | "dec" | "décembre" | "decembre" | "déc" => 12,
        _ => return None,
    })
}

/// The range `start..end` of `text` without the invisible characters (zero-width
/// space, soft hyphen...) at its ends: a date of birth read on a folded view maps
/// back over the characters the fold stripped in front of it, and they belong to
/// the link, not to the date.
pub(crate) fn trim_invisible(text: &str, start: usize, end: usize) -> (usize, usize) {
    let value = &text[start..end];
    let front = value.len() - value.trim_start_matches(is_default_ignorable).len();
    let value = value.trim_matches(is_default_ignorable);
    (start + front, start + front + value.len())
}

/// Whether the label starting at `start` of `text` reads as a field over a
/// spaced `,` or `;`. Past blanks (space, no-break space) and invisible
/// characters before it, a label of [`PROSE_LABELS`] must follow a quote or a
/// delimiter (`,` `;` `|` tab `(` `[` `:` `-` `–` `—` `/`); any other label
/// must not follow a word of [`DETERMINERS`]. Each scan stops at the first
/// character that is not a blank, then reads at most six letters: linear.
fn field_start(text: &str, start: usize, prose: bool) -> bool {
    let mut before = text[..start]
        .chars()
        .rev()
        .skip_while(|&ch| matches!(ch, ' ' | '\u{a0}') || is_default_ignorable(ch))
        .peekable();
    if prose {
        return before
            .next()
            .is_some_and(|ch| ",;|\t([:-–—/\"'“”‘’".contains(ch));
    }
    let mut word = String::new();
    while let Some(ch) = before.next_if(|ch| ch.is_alphabetic()) {
        if word.len() > 6 {
            return true;
        }
        word.insert(0, ch);
    }
    let start_of_word = !before.peek().is_some_and(|ch| ch.is_alphanumeric());
    !(start_of_word && DETERMINERS.contains(&word.to_lowercase().as_str()))
}

/// The first byte past the link after a label ending at `from`: blanks, at
/// most one line break, `:`, `=`, `-`, `–`, `—`, `|`, `*`, and the CSV marks `,`
/// and `;`, within [`MAX_LINK`] bytes, and whether a CSV mark there has a blank
/// after it and none before (`DOB, 12/…`, not `DOB , 12/…`). `None` past the
/// bound or a second line break.
fn link(text: &str, from: usize) -> Option<(usize, bool)> {
    let mut lines = 0;
    let (mut mark, mut spaced, mut blank) = (false, false, false);
    for (at, ch) in text[from..].char_indices() {
        if at > MAX_LINK {
            return None;
        }
        let is_blank = matches!(ch, ' ' | '\t' | '\r' | '\n' | '\u{a0}');
        spaced |= mark && is_blank;
        mark = matches!(ch, ',' | ';') && !blank;
        blank = is_blank;
        match ch {
            '\n' if lines == 0 => lines += 1,
            ' ' | '\t' | '\r' | '\u{a0}' | ':' | '：' | '=' | '-' | '–' | '—' | '|' | '*' | ','
            | ';' => {}
            '"' | '\'' | '“' | '”' | '‘' | '’' | '_' => {}
            ch if is_default_ignorable(ch) => {}
            _ => return Some((from + at, spaced)),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dates(text: &str) -> Vec<&str> {
        DobLabelRecognizer::new()
            .analyze(text)
            .iter()
            .map(|span| &text[span.start..span.end])
            .collect()
    }

    #[test]
    fn a_labelled_date_is_read_and_a_bare_one_is_not() {
        assert_eq!(dates("Date of birth: 14 March 1987"), ["14 March 1987"]);
        assert_eq!(dates("dob: March 14, 1987"), ["March 14, 1987"]);
        assert_eq!(dates("Né le 14/03/1987"), ["14/03/1987"]);
        assert_eq!(dates("Né le 14 févr. 1987"), ["14 févr. 1987"]);
        assert!(dates("Invoice date 14/03/1987").is_empty());
        assert!(dates("Adobe 14/03/2024").is_empty());
        assert!(dates("born in 1987").is_empty());
        assert!(dates("Date of birth\n\n14/03/1987").is_empty());
        assert_eq!(dates("DOB: 12 03 1987"), ["12 03 1987"]);
        assert_eq!(dates("Date   of birth: 12 March 87"), ["12 March 87"]);
        assert_eq!(dates("Né(e)  le 12 mars 87"), ["12 mars 87"]);
        assert_eq!(dates("DOB12/03/1987"), ["12/03/1987"]);
        // A value glued to the label ends where a date ends.
        assert_eq!(dates("D.O.B 12.3.87"), ["12.3.87"]);
        assert_eq!(dates("DDN: 12/03/1987"), ["12/03/1987"]);
        assert_eq!(dates("{\"DOB\": \"12/03/1987\"}"), ["12/03/1987"]);
        assert_eq!(dates("DOB: ____ 12/03/1987"), ["12/03/1987"]);
        assert_eq!(dates("D0B: I2/O3/1987"), ["I2/O3/1987"]);
        assert_eq!(dates("DOB: 12/031987"), ["12/031987"]);
        assert!(dates("{\"DOB\": null}").is_empty());
        assert!(dates("DOB: OO/OO/OOOO").is_empty());
        assert!(dates("ADDN 12/03/2026").is_empty());
        assert!(dates("DOB2 12/03/1987").is_empty());
        assert!(dates("Order 12 03 1987 units").is_empty());
        assert!(dates("Os-born 14/03/2024").is_empty());
        assert!(dates("invoice_dob: 14/03/2024").is_empty());
        assert!(dates("dob_date 14/03/2024").is_empty());
        // CSV key, value and an ISO timestamp (seal r2 repros, fictional dates).
        assert_eq!(dates("dob,12/03/1987"), ["12/03/1987"]);
        assert_eq!(dates("\"dob\",\"12/03/1987\""), ["12/03/1987"]);
        assert_eq!(dates("DDN;12/03/1987"), ["12/03/1987"]);
        assert_eq!(
            dates("{\"birthDate\": \"1987-03-12T00:00:00Z\"}"),
            ["1987-03-12"]
        );
        assert_eq!(dates("DOB: 1987-03-12T00:00:00"), ["1987-03-12"]);
        assert!(dates("Name;DDN\nAlice;12/03/1987").is_empty());
        assert!(dates("dob, invoice 12/03/2026").is_empty());
        assert!(dates("created_at: 2026-03-12T10:00:00Z").is_empty());
        // Spaced `,` / `;` (OCR-KERNEL-3b-1-TODO; more in tests/).
        assert_eq!(dates("Theodore DOB, 12/03/1987"), ["12/03/1987"]);
        assert_eq!(dates("Alice\tborn, 12/03/1987"), ["12/03/1987"]);
        assert!(dates("Alice born, 12/03/1987").is_empty());
        assert!(dates("the DOB, 12/03/2026 deadline").is_empty());
    }

    #[test]
    fn only_a_calendar_date_is_read() {
        for text in [
            "DOB: 31.02.2000",
            "DOB: 31 February 1987",
            "DOB: 14/13/1987",
            "DOB: 29.02.1900",
            "DOB: February 30, 1987",
            "DOB: 1987-04-31",
            "Né le 31 févr. 1987",
            "née le 31 avr. 1987",
        ] {
            assert!(dates(text).is_empty(), "{text:?}");
        }
        assert_eq!(dates("DOB: 29.02.2000"), ["29.02.2000"]);
        assert_eq!(dates("DOB: 28 February 1987"), ["28 February 1987"]);
        assert_eq!(dates("dob: Sept. 9, 1987"), ["Sept. 9, 1987"]);
        assert_eq!(dates("DOB: 14/03/87"), ["14/03/87"]);
    }

    #[test]
    fn every_month_name_has_a_number() {
        for name in MONTHS.split('|').map(str::trim) {
            assert!(month_number(name).is_some(), "{name:?}");
        }
    }
}
