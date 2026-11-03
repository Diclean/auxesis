//! A sensitive label followed by its value (LABEL-VALUE-1).
//!
//! One lexicon (`data/label-value-v1.tsv`) maps a label (`MRN`, `blood type`,
//! `the pin`, `Personalausweis`, `护照号`) to a class; the value after it is
//! masked when it has that class's shape:
//!
//! * `SECRET`: one token of 4+ characters holding a digit or a symbol, or a
//!   quoted value (`the password might be G9$rP2zT@qWk`, `the pin, 719836`);
//! * `COOKIE`: the rest of the line when it holds `=` (`Cookie: sid=…; b=…`);
//! * `ID` and `HEALTH`: an alphanumeric run with `-./` or single-space groups,
//!   5+ (ID) or 4+ (HEALTH) alphanumerics with 2+ digits (`CNI : 1234…`);
//! * `BLOOD`: a blood group with its sign (`O negative`, `AB+`, `B Rh-`), or
//!   bare after `:` when written in capitals;
//! * `MEMBER`: a `HEALTH` number after a label that is health only near a
//!   health word (`member ID` by a health insurer, not a gym's) (HEALTH-LABEL).
//!
//! The link between label and value is bounded: decoration (`**`, quotes, `|`,
//! and for an ID or health label an opening parenthesis), `:`, `=`, `#`, `,`,
//! number words (`no.`, `Nr`,
//! `n°`, and one glued to its value: `n°12AB34567`) and prose links (`is`,
//! `might be`, `changed … to` reads as `to`; a health or ID label also takes
//! `of`, `such as`, `c'est` and `for … is`, ID-LABEL), at most [`MAX_LINK`] bytes with each blank run
//! counted once. A `name=value; Path=/` cookie is masked too.
//! Every lookup is a bounded look-ahead from one automaton match: linear.
//! Values are `SECRET`, `NATIONAL_ID` or `HEALTH`, classes open mode removes.

use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, MatchKind};
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::recognizer::Recognizer;
use crate::recognizers::mrz::PassportMrzRecognizer;
use crate::recognizers::secrets::linked_clause_end;
use crate::span::{EntityKind, Span};

const DATA: &str = include_str!("../../data/label-value-v1.tsv");

/// The name echoed in [`Span::recognizer`].
const NAME: &str = "label_value";

/// Longest link between a label and its value, a blank run counted once.
const MAX_LINK: usize = 24;
/// Longest link in raw bytes, so a padded table cell still links.
const MAX_LINK_RAW: usize = 64;
/// Longest ID or health number, in bytes.
const MAX_ID: usize = 40;
/// Longest ASCII tag glued to a blood label or sign (`ref`, `ok`), HEALTH-LABEL-1.
const MAX_TAG: usize = 4;
/// Rows read under a blood-group column header.
const MAX_ROWS: usize = 10_000;
/// Longest header line a blood column is read under, in bytes.
const MAX_HEADER: usize = 4_096;

/// Words that may sit between a label and its value. A number word also counts
/// as the strong link a `punct` label needs.
const LINKS: &str = "is was are were be been might may will would should could must now still \
    currently set changed updated to est etait sera devient ist lautet war je";
/// Links only a health number, a blood group or an ID takes (`a blood type of O+`,
/// `a tax ID of 98-…`, `ma cni c'est …`): a secret after `of` stays as main.
const HEALTH_LINKS: &str = "of such as like c'est";
/// Words that make a `MEMBER` label a health one when one stands within
/// [`CUE_WINDOW`] bytes of it (folded: no accents, lower case).
const HEALTH_CUES: &str = "health healthcare medical patient patients clinic hospital medicare \
    medicaid dental pharmacy prescription nhs sante mutuelle hopital clinique medecin";
/// Words that make a `MEMBER` label a club's or a shop's when nearer to it than
/// any health word (`health club member ID`, `gym member ID`).
const NON_HEALTH_CUES: &str = "gym fitness loyalty rewards points club";
/// How far around a `MEMBER` label and its value a cue is looked for.
const CUE_WINDOW: usize = 120;
/// The links after which a plain word is a value (`might be`, `set to`, `est`):
/// English and French only, the languages of K-SECRET-TAIL's stopwords.
const PROSE_LINKS: &str = "is was are were be been set changed updated est etait sera";
/// Plain words a prose link may bring that are no value (`password, then log in`).
const FUNCTION_WORDS: &str = "which that then please but so if as when where while you your \
    it its this these we our they he she also with without because since though however \
    there their only just even still very including such sent shared provided given emailed \
    texted displayed shown available valid case sensitive different same strong weak secure \
    long short";
const NUMBER_WORDS: &str =
    "no nr n° nº num number numero nummer nommer szam szama stevilka 号 号码 號碼 是 为 為";
/// Whether `value` is a real date (`2024-10-01`, `01/10/2024`, `1.10.24`):
/// three digit groups over one kind of `-`, `/` or `.`, read year first
/// (`yyyy-mm-dd`, `yy-mm-dd`) or year last (`dd-mm-yyyy`, `mm-dd-yy`), with a
/// month of 1 to 12 and a day of 1 to 31 in one of those readings. A
/// `number`-linked label's value is never one (`licence number: 2024-10-01`,
/// ID-LABEL-1); `99-99-99` or `12-34-56` is no date, so it stays an ID.
fn is_date(value: &str) -> bool {
    let Some(sep) = value.chars().find(|c| matches!(c, '-' | '/' | '.')) else {
        return false;
    };
    let groups: Vec<&str> = value.split(sep).collect();
    if groups.len() != 3
        || !groups
            .iter()
            .all(|g| (1..=4).contains(&g.len()) && g.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let lens: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    let n: Vec<u32> = groups.iter().filter_map(|g| g.parse().ok()).collect();
    let date = |month: u32, day: u32| (1..=12).contains(&month) && (1..=31).contains(&day);
    let year_first = (lens[0] == 4 || lens[0] == 2) && lens[1] <= 2 && lens[2] <= 2;
    let year_last = lens[0] <= 2 && lens[1] <= 2 && (lens[2] == 4 || lens[2] <= 2);
    year_first && date(n[1], n[2]) || year_last && (date(n[1], n[0]) || date(n[0], n[1]))
}

/// Words that make a `number`-linked label a business's, right before it.
const BUSINESS_WORDS: &str = "certificate software product business trade company vendor \
    export import site server app seat volume";
/// Business words read in an aside only (ID-LABEL-2 r1), not before a label:
/// `the corporate licence number …` stays masked as on main.
const BUSINESS_ASIDES: [&str; 4] = ["corporate", "commercial", "organisation", "organization"];
const QUOTES: &str = "\"'`“”‘’«»„「」『』";
const BLOOD_SIGNS: &str = "positive positif positiv pozitiv pozitivna pozitiven pos negative \
    negatif negativ negativna negativen neg 阳性 阴性";
/// A cookie attribute after `; ` marks the `name=value` before it as a cookie.
const COOKIE_ATTRIBUTES: &str = "path= domain= expires= samesite= httponly secure";
/// The words of a passport label, folded (ID-LABEL-2): the spaced CN passport
/// number is read behind one of these and behind no other ID label.
const PASSPORT_WORDS: &str = "passport passportno passportnumber passports passeport \
    pasaporte 护照 护照号 护照号码";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Secret,
    Cookie,
    Id,
    Health,
    Blood,
    Member,
}

struct Label {
    class: Class,
    /// Only after `:`, `=`, `#` or a number word.
    punct: bool,
    /// Only when a number word comes first (`licence no.`, ID-LABEL-1).
    numbered: bool,
    cjk_start: bool,
    cjk_end: bool,
}

struct Lexicon {
    automaton: AhoCorasick,
    labels: Vec<Label>,
}

static LEXICON: LazyLock<Lexicon> = LazyLock::new(|| {
    let (mut patterns, mut labels) = (Vec::new(), Vec::new());
    for line in DATA
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let [_, class, link, label] = cols[..] else {
            panic!("label-value-v1.tsv: four columns: {line:?}")
        };
        let class = match class {
            "SECRET" => Class::Secret,
            "COOKIE" => Class::Cookie,
            "ID" => Class::Id,
            "HEALTH" => Class::Health,
            "BLOOD" => Class::Blood,
            "MEMBER" => Class::Member,
            _ => panic!("label-value-v1.tsv: class {class:?}"),
        };
        let label = fold(label).0;
        let cjk = |ch: Option<char>| ch.is_some_and(is_cjk);
        labels.push(Label {
            class,
            punct: link == "punct",
            numbered: link == "number",
            cjk_start: cjk(label.chars().next()),
            cjk_end: cjk(label.chars().last()),
        });
        patterns.push(label);
    }
    let automaton = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(&patterns)
        .expect("label-value lexicon builds");
    Lexicon { automaton, labels }
});

fn is_cjk(ch: char) -> bool {
    matches!(ch, '\u{3400}'..='\u{9FFF}' | '\u{F900}'..='\u{FAFF}' | '\u{20000}'..='\u{2FA1F}')
}

/// `text` folded (lower case, no accents, `_` and `-` as a space, a markdown
/// escape `\_` dropped, curly apostrophes straight) and, per folded byte, the
/// original byte it came from (plus one entry for the end).
pub(crate) fn fold(text: &str) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len() + 1);
    let mut chars = text.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        let mut push = |c: char, out: &mut String| {
            map.extend(std::iter::repeat_n(at, c.len_utf8()));
            out.push(c);
        };
        match ch {
            '\\' if chars
                .peek()
                .is_some_and(|(_, next)| next.is_ascii_punctuation()) => {}
            '_' | '-' | '\u{2010}' | '\u{2011}' => push(' ', &mut out),
            '’' | '‘' | 'ʼ' => push('\'', &mut out),
            _ => {
                for lower in ch.to_lowercase() {
                    for c in std::iter::once(lower)
                        .nfd()
                        .filter(|c| !is_combining_mark(*c))
                    {
                        push(c, &mut out);
                    }
                }
            }
        }
    }
    map.push(text.len());
    (out, map)
}

/// The recogniser for a sensitive label followed by its value.
#[derive(Clone, Copy, Debug, Default)]
pub struct LabelValueRecognizer;

impl LabelValueRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for LabelValueRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[
            EntityKind::Secret,
            EntityKind::NationalId,
            EntityKind::Health,
        ]
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let lexicon = &*LEXICON;
        let (folded, map) = fold(text);
        let newlines: Vec<usize> = text.match_indices('\n').map(|(at, _)| at).collect();
        let equals: Vec<usize> = text.match_indices('=').map(|(at, _)| at).collect();
        // A value or token already read ends at `reach`: a label inside it is part of
        // it, so no byte is read twice (linear without a value cap).
        let (mut spans, mut reach) = (Vec::new(), 0);
        // Rows a blood column already read end at `rows`: a header among them is
        // not read again, so each row is read once.
        let mut rows = 0;
        for hit in lexicon.automaton.find_iter(&folded) {
            let label = &lexicon.labels[hit.pattern().as_usize()];
            if map[hit.start()] < reach {
                continue;
            }
            let before = folded[..hit.start()].chars().next_back();
            let after = folded[hit.end()..].chars().next();
            if inside_word(text, map[hit.start()])
                || !label.cjk_start && before.is_some_and(char::is_alphanumeric)
            {
                continue;
            }
            if label.class == Class::Blood {
                let (start, end) = (map[hit.start()], map[hit.end()]);
                let next = newlines.partition_point(|&at| at < start);
                let line = (
                    next.checked_sub(1).map_or(0, |n| newlines[n] + 1),
                    newlines.get(next).map_or(text.len(), |&at| at),
                );
                spans.extend(blood_column(text, (start, end), line, &mut rows));
            }
            if !label.cjk_end && after.is_some_and(char::is_alphanumeric) {
                // A blood group glued to its label, maybe behind a short tag
                // (`Blood typerefAB negative`), HEALTH-LABEL-1.
                if let Some(end) = (label.class == Class::Blood)
                    .then(|| glued_blood(text, map[hit.end()]))
                    .flatten()
                {
                    spans.push(Span::new(
                        EntityKind::Health,
                        map[hit.end()],
                        end,
                        1.0,
                        NAME,
                    ));
                    reach = reach.max(end);
                }
                continue;
            }
            let wide = !matches!(label.class, Class::Secret | Class::Cookie);
            let aside = label.class == Class::Id;
            let Some((at, strong, prose, crossed)) = link(&folded, hit.end(), wide, aside) else {
                continue;
            };
            if (label.punct && !strong)
                || (label.numbered && !numbered(&folded[..hit.start()], &folded[hit.end()..]))
            {
                continue;
            }
            let start = map[at];
            let line = newlines
                .get(newlines.partition_point(|&at| at < start))
                .map_or(text.len(), |&at| at);
            let found = match label.class {
                Class::Secret => {
                    let (end, read) = secret(text, start, line, prose);
                    reach = reach.max(read);
                    end
                }
                Class::Cookie => {
                    let eq = equals.get(equals.partition_point(|&at| at < start));
                    eq.is_some_and(|&at| at < line)
                        .then(|| cookie(text, start, line))
                        .flatten()
                }
                Class::Id => {
                    let read = |start: usize| {
                        number(text, start, 5)
                            .or_else(|| {
                                spaced_passport(text, &folded[hit.start()..hit.end()], start)
                            })
                            .filter(|&end| !passport_covers(text, map[hit.start()], start, end))
                            .filter(|&end| {
                                !((label.numbered || crossed) && is_date(&text[start..end]))
                            })
                    };
                    read(start)
                }
                Class::Health => number(text, start, 4),
                Class::Blood => blood(text, start, strong),
                Class::Member => {
                    number(text, start, 4).filter(|&end| health_cued(text, map[hit.start()], end))
                }
            };
            if let Some(end) = found {
                let kind = match label.class {
                    Class::Secret | Class::Cookie => EntityKind::Secret,
                    Class::Id => EntityKind::NationalId,
                    Class::Health | Class::Blood | Class::Member => EntityKind::Health,
                };
                spans.push(Span::new(kind, start, end, 1.0, NAME));
                // A label inside a crossed aside is still read (`licence number
                // (password/…): …`, ID-LABEL-2 r1): the value is short, so the
                // rescan stays bounded.
                if !crossed {
                    reach = reach.max(end);
                }
            }
        }
        spans.extend(cookie_pairs(text, &folded, &map));
        spans
    }
}

/// Whether the passport rule already masks `start..end` when it reads the label
/// from `from` on: its hit then keeps its own label and score (P3), never
/// displaced by this rule.
fn passport_covers(text: &str, from: usize, start: usize, end: usize) -> bool {
    let spans = PassportMrzRecognizer::new().analyze(&text[from..end]);
    spans
        .iter()
        .any(|span| from + span.start <= start && end <= from + span.end)
}

/// Whether a health word stands within [`CUE_WINDOW`] bytes of the `MEMBER`
/// label at `from` and its value ending at `end`, nearer than any club or shop
/// word (`His health is fine; gym member ID …` is the gym's). The window is
/// bounded, so each label reads a constant span.
fn health_cued(text: &str, from: usize, end: usize) -> bool {
    let start = text.floor_char_boundary(from.saturating_sub(CUE_WINDOW));
    let stop = text.ceil_char_boundary((end + CUE_WINDOW).min(text.len()));
    let (window, map) = fold(&text[start..stop]);
    let (mut health, mut other) = (usize::MAX, usize::MAX);
    let mut at = 0;
    for word in window.split(|c: char| !c.is_alphanumeric()) {
        let (first, last) = (start + map[at], start + map[at + word.len()]);
        at += word.len()
            + window[at + word.len()..]
                .chars()
                .next()
                .map_or(0, char::len_utf8);
        let distance = if last <= from {
            from - last
        } else {
            first.saturating_sub(end)
        };
        let is = |list: &str| !word.is_empty() && list.split(' ').any(|cue| cue == word);
        if is(HEALTH_CUES) {
            health = health.min(distance);
        } else if is(NON_HEALTH_CUES) {
            other = other.min(distance);
        }
    }
    health != usize::MAX && health <= other
}

/// Whether the label at `start` sits inside a path, a host or an identifier
/// (`portal/pin-login`, `certificate_license`): after `/`, `.`, `@`, `\`, or a
/// `_`/`-` glued to a letter or digit.
fn inside_word(text: &str, start: usize) -> bool {
    let mut before = text[..start].chars().rev();
    match before.next() {
        Some('/' | '.' | '@' | '\\') => true,
        Some('_' | '-') => before.next().is_some_and(char::is_alphanumeric),
        _ => false,
    }
}

/// Skip the link after a label ending at `from` in `folded`: the value's
/// folded offset and whether a strong link (`:`, `=`, `#`, a number word) was
/// crossed (a table cell `|` is decoration), and the prose link after which a
/// plain word is a value: `Some(true)` for a word (`is`, `be`, `set`, `changed`),
/// `Some(false)` for a bare comma. `None` past the bound or a line. A `health`
/// or ID label (`wide`) also crosses [`HEALTH_LINKS`] and a `for … is` clause.
///
/// An opening parenthesis is decoration for a `wide` label only
/// (`driver_license_number (D37-…)`, ID-LABEL-2). Behind a secret or cookie
/// label it is the first byte of the value, exactly as on main: `api_key
/// (smith…)` masks from the `(`.
///
/// Behind an ID label (`aside`), one [`aside_end`] aside is crossed whole, so a
/// `:` after it is the strong link (`TIN (if applicable): …`) and its words are
/// no link (`(as applicable)`); the last field says whether one was crossed.
fn link(
    folded: &str,
    from: usize,
    wide: bool,
    aside: bool,
) -> Option<(usize, bool, Option<bool>, bool)> {
    let (mut at, mut used, mut strong, mut lines) = (from, 0, false, 0);
    let mut crossed = false;
    let mut prose = None;
    while at < folded.len() && used <= MAX_LINK && at - from <= MAX_LINK_RAW {
        let rest = &folded[at..];
        let ch = rest.chars().next()?;
        if ch.is_whitespace() {
            let run = rest.len() - rest.trim_start().len();
            lines += rest[..run].matches('\n').count();
            if lines > 1 {
                return None;
            }
            (at, used) = (at + run, used + 1);
            continue;
        }
        if aside && !crossed && ch == '(' {
            if let Some(end) = aside_end(folded, at + 1) {
                (at, used, crossed) = (end, used + 1, true);
                continue;
            }
        }
        if matches!(ch, ':' | '：' | '=' | '#') {
            strong = true;
        } else if matches!(ch, ',' | '，') {
            prose = prose.or(Some(false));
        } else if !matches!(ch, '*' | '|' | '–' | '—' | '>')
            && !(wide && ch == '(')
            && !QUOTES.contains(ch)
        {
            let word = |w: &&str| {
                rest.starts_with(*w) && (w.ends_with(is_cjk) || ends_word(&rest[w.len()..]))
            };
            if let Some(number) = NUMBER_WORDS.split(' ').find(word) {
                let dot = usize::from(rest[number.len()..].starts_with('.'));
                (at, used, strong) = (at + number.len() + dot, used + number.len() + dot, true);
                continue;
            }
            if wide && word(&"for") {
                if let Some((len, colon)) = for_clause(&rest[3..]) {
                    (at, used, strong) = (at + 3 + len, used + 4, strong || colon);
                    continue;
                }
            }
            let wide_link = || HEALTH_LINKS.split(' ').filter(|_| wide).find(word);
            if let Some(link) = LINKS.split(' ').find(word).or_else(wide_link) {
                if PROSE_LINKS.split(' ').any(|prose| prose == link) {
                    prose = Some(true);
                }
                (at, used) = (at + link.len(), used + link.len());
                continue;
            }
            return Some((at, strong, prose, crossed));
        }
        (at, used) = (at + ch.len_utf8(), used + ch.len_utf8());
    }
    None
}

/// The folded offset past a short aside whose `(` ends right before `at`
/// (ID-LABEL-2): one to thirty letters, blanks, `'`, `-` or `/`, then `)`. No
/// digit, so a value in parentheses stays the value, and no business word
/// (`licence number (business): …` is a business's). At most 31 characters.
fn aside_end(folded: &str, at: usize) -> Option<usize> {
    let rest = &folded[at..];
    let len = rest
        .char_indices()
        .take(31)
        .find(|&(_, c)| !(c.is_alphabetic() || matches!(c, ' ' | '\'' | '’' | '-' | '/')))
        .filter(|&(_, c)| c == ')')?
        .0;
    let aside = &rest[..len];
    let words = || {
        aside
            .split(|c: char| !c.is_alphabetic())
            .filter(|w| !w.is_empty())
    };
    let business = |w: &str| {
        BUSINESS_WORDS
            .split(' ')
            .chain(BUSINESS_ASIDES)
            .any(|b| b == w)
    };
    (words().next().is_some() && !words().any(business)).then_some(at + len + 1)
}

/// Whether a number word comes first in `rest`, past blanks (`licence number …`,
/// `licence no. …`, `licence n°12AB34567`, ID-LABEL-1): a word that only starts
/// with one (`licence notes`) is none. A business word right before the label
/// makes it a business's (`the certificate license number …`).
///
/// The business word is read in the label's own field only: a line break, `:`,
/// `;` or `.` ends the field before (`Purpose: business\nLicence number …` is
/// the owner's). One line break may stand inside the label
/// (`licence\nnumber: …`, `licence\r\nnumber: …`).
fn numbered(before: &str, rest: &str) -> bool {
    let near = &before[before.floor_char_boundary(before.len().saturating_sub(32))..];
    let field = near.rsplit(['\n', ':', ';', '.']).next().unwrap_or(near);
    let word = field
        .split(|c: char| !c.is_alphanumeric())
        .rev()
        .find(|w| !w.is_empty());
    if word.is_some_and(|word| BUSINESS_WORDS.split(' ').any(|w| w == word)) {
        return false;
    }
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest
        .strip_prefix("\r\n")
        .or_else(|| rest.strip_prefix('\n'))
        .map_or(rest, |tail| tail.trim_start_matches([' ', '\t']));
    NUMBER_WORDS.split(' ').any(|word| {
        rest.strip_prefix(word)
            .is_some_and(|tail| ends_word(tail) || tail.starts_with(|c: char| c.is_ascii_digit()))
    })
}

/// After a health label's `for`, one to three words then `is`, `was` or `:`
/// (`medical record number for this donor is …`): the folded bytes up to and
/// with that link, and whether it was a `:`. `None` for any other shape.
fn for_clause(rest: &str) -> Option<(usize, bool)> {
    let blank = |s: &str| s.len() - s.trim_start_matches([' ', '\t']).len();
    let mut at = 0;
    for _ in 0..3 {
        let space = blank(&rest[at..]);
        let word = rest[at + space..]
            .find(|c: char| !c.is_alphanumeric() && c != '\'')
            .unwrap_or(rest.len() - at - space);
        if space == 0 || word == 0 {
            return None;
        }
        at += space + word;
        let skip = blank(&rest[at..]);
        let after = &rest[at + skip..];
        if after.starts_with(':') {
            return Some((at + skip + 1, true));
        }
        let link = ["is", "was"].into_iter().find(|w| after.starts_with(w));
        if let Some(link) = link.filter(|w| skip > 0 && ends_word(&after[w.len()..])) {
            return Some((at + skip + link.len(), false));
        }
    }
    None
}

/// The quote char just before `start`, when it opens the value: it follows a
/// blank or a separator, so the quote closing `'Change PIN'` never opens one.
fn opening_quote(text: &str, start: usize) -> Option<char> {
    let mut before = text[..start].chars().rev();
    let quote = before.next().filter(|c| QUOTES.contains(*c))?;
    let opens = |c: char| c.is_whitespace() || ":=(,[{：".contains(c);
    before.next().is_none_or(opens).then_some(quote)
}

/// The end of a secret value at `start` on a line ending at `line`, and how far the
/// read went. A quoted value runs to its closing quote, or the line end when it has
/// none. Else one token, secret-shaped, or after a prose link a plain word that is
/// no stopword, then its clause (K-SECRET-TAIL). No byte cap: the registry splits a
/// long span.
fn secret(text: &str, start: usize, line: usize, prose: Option<bool>) -> (Option<usize>, usize) {
    let rest = &text[start..line];
    if rest.starts_with(['⟦', '[']) {
        return (None, start);
    }
    if let Some(quote) = opening_quote(text, start) {
        let close = rest.find(|c: char| c == quote || QUOTES.contains(c) && c != '\'');
        let value = rest[..close.unwrap_or(rest.len())].trim_end();
        let end = start + value.len();
        return ((value.chars().count() >= 4).then_some(end), end);
    }
    let cjk = rest.starts_with(is_cjk);
    let token_end = rest
        .find(|c: char| c.is_whitespace() || "，。；、）」』|".contains(c) || (!cjk && is_cjk(c)))
        .unwrap_or(rest.len());
    let token =
        rest[..token_end].trim_end_matches(|c: char| ",;:)]}>*`".contains(c) || QUOTES.contains(c));
    let symbol = |c: char| !c.is_alphanumeric() && !".-'’".contains(c);
    // An HTML tag or attribute (`id="pin"`, `Entry</title>`) is markup, not a value.
    let markup = token.contains(['<', '>']) || token.contains("=\"") || token.contains("='");
    let long = token.chars().count() >= 4;
    let shaped = token.chars().any(|c| c.is_ascii_digit()) || token.chars().any(symbol);
    let word = token.trim_end_matches(['.', '!', '?']);
    let plain = !FUNCTION_WORDS
        .split(' ')
        .any(|w| w.eq_ignore_ascii_case(word));
    let end = start + token.len();
    let plain = match prose {
        Some(true) => plain,
        // After a bare comma a plain word is an apposition: its clause is that word
        // (`the password, sunflowerfield, opens it`), never a list (`passwords, two-
        // factor authentication`).
        Some(false) => plain && linked_clause_end(text, start, end, line) == Some(end),
        None => false,
    };
    if markup || !long || !(shaped || plain) {
        return (None, start + token_end);
    }
    if prose.is_none() {
        return (Some(end), end);
    }
    let clause = linked_clause_end(text, start, end, line);
    (clause, clause.unwrap_or(end))
}

/// The rest of the line at `start`, up to `line`, as a cookie header's value.
fn cookie(text: &str, start: usize, line: usize) -> Option<usize> {
    let value = text[start..line].trim_end();
    (!value.starts_with(['⟦', '['])).then_some(start + value.len())
}

/// The end of an ID or record number at `start`: alphanumeric groups joined by
/// one of `-./` or one space (a spaced group must hold a digit), with at least
/// `min` alphanumerics, two of them digits.
///
/// Main's own reading comes first, so `Tax ID no1234` is six alphanumerics —
/// the sign's letters are two of them — and reads exactly as it reads on main.
/// Only a sign main's reading cannot see past (`n°12AB34567`, where `°` ends
/// the alphanumeric run) is read from behind the sign, and there the sign's own
/// letters count toward `min` as well (ID-LABEL-2). The mask starts at the
/// label's own `start` either way, so it covers the sign and the digits behind
/// it.
fn number(text: &str, start: usize, min: usize) -> Option<usize> {
    number_from(text, start, min, 0).or_else(|| match glued_sign(text, start) {
        0 => None,
        sign => number_from(
            text,
            start + sign,
            min,
            text.as_bytes()[start..start + sign]
                .iter()
                .filter(|b| b.is_ascii_alphanumeric())
                .count(),
        ),
    })
}

/// [`number`] read from `from`, with `carry` alphanumerics already read in front
/// of it (the letters of a glued sign) counted toward `min`.
fn number_from(text: &str, from: usize, min: usize, carry: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let (mut at, mut end, mut alnum, mut digits) = (from, from, carry, 0);
    while at < bytes.len() && at - from <= MAX_ID {
        let run = bytes[at..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric())
            .count();
        if run == 0 {
            break;
        }
        let group_digits = bytes[at..at + run]
            .iter()
            .filter(|b| b.is_ascii_digit())
            .count();
        // A spaced group joins only a value that already holds a digit, so a word
        // before a year stays clear (`ID card renewal 2026`).
        if at > from && bytes[at - 1] == b' ' && (group_digits == 0 || digits == 0) {
            break;
        }
        (alnum, digits, end) = (alnum + run, digits + group_digits, at + run);
        match bytes.get(end..end + 2) {
            Some([b'-' | b'.' | b'/' | b' ', next]) if next.is_ascii_alphanumeric() => at = end + 1,
            _ => break,
        }
    }
    let boundary = !text[end..].starts_with(char::is_alphanumeric);
    (alnum >= min && digits >= 2 && boundary).then_some(end)
}

/// The bytes of the number sign glued to `start` (`n°`, `nº`, `no`), when a
/// digit follows it. A word that only starts with a sign is no sign at all
/// (`nothing`, `notes`), so `Tax ID nothing12` keeps main's reading.
fn glued_sign(text: &str, start: usize) -> usize {
    let rest = &text[start..];
    let sign = match rest.chars().next() {
        Some('n' | 'N') => rest[1..]
            .chars()
            .next()
            .filter(|c| matches!(c, '°' | 'º' | 'ª' | 'o' | 'O'))
            .map_or(0, |c| 1 + c.len_utf8()),
        _ => 0,
    };
    if sign > 0 && rest[sign..].starts_with(|c: char| c.is_ascii_digit()) {
        sign
    } else {
        0
    }
}

/// The end of a CN passport number written spaced behind a **passport** label:
/// one or two capital letters, then two groups of four digits
/// (`E 1234 5678`, ID-LABEL-2). The shape is a passport number's, so a tax or a
/// licence label does not claim it (`tax id: E 1234 5678` is a tax number and
/// stays clear). It is read by hand because [`number`] joins a spaced group only
/// to a value that already holds a digit, and the leading `E` holds none.
fn spaced_passport(text: &str, label: &str, start: usize) -> Option<usize> {
    if !passport_label(label) {
        return None;
    }
    let bytes = text.as_bytes();
    let letters = count_upper(bytes, start);
    if !(1..=2).contains(&letters) {
        return None;
    }
    let mut end = start + letters;
    for _ in 0..2 {
        // Each group is one blank, then exactly four digits.
        if bytes.get(end) != Some(&b' ') || count_digits(bytes, end + 1) != 4 {
            return None;
        }
        end += 5;
    }
    (!text[end..].starts_with(char::is_alphanumeric)).then_some(end)
}

/// Whether a folded label holds a passport word, so a spaced CN passport number
/// behind it is one (`passport`, `passport number`, `passportno`, `passeport`,
/// `numero de passeport`, `护照`, `护照号`, `护照号码`).
fn passport_label(label: &str) -> bool {
    label
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| PASSPORT_WORDS.split(' ').any(|p| p == word))
}

/// The run of ASCII capitals at `at`, in bytes.
fn count_upper(bytes: &[u8], at: usize) -> usize {
    bytes
        .get(at..)
        .unwrap_or_default()
        .iter()
        .take_while(|b| b.is_ascii_uppercase())
        .count()
}

/// The run of ASCII digits at `at`, in bytes.
fn count_digits(bytes: &[u8], at: usize) -> usize {
    bytes
        .get(at..)
        .unwrap_or_default()
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count()
}

/// The end of a blood group at `start` (`O negative`, `AB+`, `A型Rh阴性`); a bare
/// group counts only after a strong link and in capitals (`Blood type: O`).
fn blood(text: &str, start: usize, strong: bool) -> Option<usize> {
    let rest = &text[start..];
    let group = ["AB", "ab", "A", "B", "O", "0", "a", "b", "o"]
        .into_iter()
        .find(|g| rest.starts_with(g))?;
    let mut at = group.len();
    if !ends_word(&rest[at..]) && !rest[at..].starts_with(['+', '-', '−']) {
        return None;
    }
    let bare = (strong && group.chars().all(|c| !c.is_lowercase())).then_some(start + at);
    at += rest[at..].strip_prefix('型').map_or(0, |_| '型'.len_utf8());
    // The sign, read on a short folded view (accents, case, Unicode blanks) whose map
    // leads back to the original end.
    let view = &rest[at..rest.floor_char_boundary(at + 48)];
    let (folded, map) = fold(view);
    // Blanks before the sign, across one line break (`AB\r\nnegative`, HEALTH-LABEL-1).
    let skip = |f: usize| {
        let mut breaks = 0;
        f + folded[f..]
            .find(|c: char| {
                breaks += usize::from(c == '\n');
                !c.is_whitespace() || breaks > 1
            })
            .unwrap_or(folded.len() - f)
    };
    // A `-` sign reads as a blank once folded, so it is looked for in the raw view
    // right after the group or `Rh` (`AB-`, `O Rh-`); a `-` before a letter is a
    // hyphen (`A-negative`) and goes on to the sign word (HEALTH-LABEL).
    let dash = |f: usize| {
        let raw = &view[map[f]..];
        (raw.starts_with('-') && !raw[1..].starts_with(char::is_alphanumeric))
            .then_some(start + at + map[f] + 1)
    };
    let mut early = dash(0);
    let mut f = skip(0);
    if folded[f..].starts_with("rh") {
        let after = f + if folded[f..].starts_with("rhd") { 3 } else { 2 };
        early = early.or(dash(after));
        f = skip(after);
    }
    if view[map[f]..].starts_with(['+', '-', '−']) {
        return Some(start + at + map[f] + view[map[f]..].chars().next().map_or(0, char::len_utf8));
    }
    // A whole sign word may carry a short glued tag (`negativeok`, HEALTH-LABEL-1).
    let sign = BLOOD_SIGNS.split(' ').find_map(|sign| {
        let rest = folded[f..].strip_prefix(sign)?;
        // An adverb is no tag (`negatively`, `positively`).
        let tag = rest.bytes().take_while(u8::is_ascii_alphanumeric).count();
        if tag > MAX_TAG || tag > 0 && rest[..tag].ends_with("ly") {
            return None;
        }
        ends_word(&rest[tag..]).then_some(sign.len() + tag)
    });
    // The longer reading wins, so a value main read whole is never cut short.
    sign.map_or(bare, |len| Some(start + at + map[f + len]))
        .max(early)
}

/// The end of a blood group glued to its label at `from`, behind at most
/// [`MAX_TAG`] ASCII letters or digits (`Blood typeAB-`, `Blood typerefAB
/// negative`). The group must carry its sign.
fn glued_blood(text: &str, from: usize) -> Option<usize> {
    let tag = text[from..]
        .bytes()
        .take_while(u8::is_ascii_alphanumeric)
        .count();
    (0..=tag.min(MAX_TAG)).find_map(|skip| blood(text, from + skip, false))
}

/// The cells under every blood-group column of the header holding the label at
/// `start..end` (`id,blood_type,city` then `17,AB negative,Lyon`), HEALTH-LABEL-1.
/// The label must fill its cell; the delimiter is `,`, `;`, a tab or `|`. At most
/// [`MAX_ROWS`] rows are read, up to a blank line; the rows read end at `rows`,
/// and a header before that is skipped.
fn blood_column(
    text: &str,
    (start, end): (usize, usize),
    (line_start, line_end): (usize, usize),
    rows: &mut usize,
) -> Vec<Span> {
    if line_start < *rows || line_end - line_start > MAX_HEADER {
        return Vec::new();
    }
    let before = text[line_start..start]
        .trim_end_matches([' ', '"'])
        .chars()
        .next_back();
    let after = text[end..line_end]
        .trim_start_matches([' ', '"', '\r'])
        .chars()
        .next();
    let delimiter = match (before, after) {
        (_, Some(d @ (',' | ';' | '\t' | '|'))) | (Some(d @ (',' | ';' | '\t' | '|')), None) => d,
        _ => return Vec::new(),
    };
    if before.is_some_and(|b| b != delimiter) {
        return Vec::new();
    }
    let (header, _) = cells(text, line_start, delimiter);
    let columns: Vec<usize> = (0..header.len())
        .filter(|&n| is_blood_label(&text[header[n].0..header[n].1]))
        .collect();
    let mut spans = Vec::new();
    let mut at = line_end;
    for _ in 0..MAX_ROWS {
        if at >= text.len() {
            break;
        }
        let (row, row_end) = cells(text, at + 1, delimiter);
        if text[at + 1..row_end].trim().is_empty() {
            break;
        }
        at = row_end;
        for &(cell_start, cell_end) in columns.iter().filter_map(|&n| row.get(n)) {
            if cell_start < cell_end
                && blood(text, cell_start, true).is_some_and(|value| value >= cell_end)
            {
                spans.push(Span::new(
                    EntityKind::Health,
                    cell_start,
                    cell_end,
                    1.0,
                    NAME,
                ));
            }
        }
    }
    *rows = at;
    spans
}

/// Whether a header cell is a blood-group label, whole (`blood_type`, `Groupe sanguin`).
fn is_blood_label(cell: &str) -> bool {
    let lexicon = &*LEXICON;
    let folded = fold(cell).0;
    lexicon.automaton.find(&folded).is_some_and(|hit| {
        hit.start() == 0
            && hit.end() == folded.len()
            && lexicon.labels[hit.pattern().as_usize()].class == Class::Blood
    })
}

/// The cells of the delimited row at `from`, up to its line end, and that end,
/// RFC 4180 style: a cell that opens with `"` runs to its closing `"`, a doubled
/// `""` in it being a quote, so a delimiter inside it splits nothing
/// (`"fictional,subject",AB negative`). A quote never runs past its line, so a
/// stray one costs only its row. Each cell is its content without the quotes and
/// the blanks around it. One pass over the row: linear.
fn cells(text: &str, from: usize, delimiter: char) -> (Vec<(usize, usize)>, usize) {
    let end = text[from..].find('\n').map_or(text.len(), |n| from + n);
    let next = |at: usize| text[at..end].find(delimiter).map_or(end, |n| at + n);
    let (mut out, mut at) = (Vec::new(), from);
    loop {
        let lead = at + (text[at..end].len() - text[at..end].trim_start_matches(' ').len());
        let (content, stop) = if text[lead..end].starts_with('"') {
            let mut close = lead + 1;
            loop {
                match text[close..end].find('"') {
                    None => close = end,
                    Some(n) if text[close + n + 1..end].starts_with('"') => {
                        close += n + 2;
                        continue;
                    }
                    Some(n) => close += n,
                }
                break;
            }
            ((lead + 1, close), next(close))
        } else {
            let stop = next(lead);
            let trimmed = text[lead..stop].trim_end_matches([' ', '"', '\r']);
            ((lead, lead + trimmed.len()), stop)
        };
        out.push(content);
        if stop >= end {
            return (out, end);
        }
        at = stop + 1;
    }
}

fn ends_word(rest: &str) -> bool {
    !rest.starts_with(|c: char| c.is_alphanumeric() && !is_cjk(c))
}

/// `name=value; Path=/`: the value of the cookie pair before a cookie attribute.
fn cookie_pairs<'a>(
    text: &'a str,
    folded: &'a str,
    map: &'a [usize],
) -> impl Iterator<Item = Span> + 'a {
    // Each pair is searched back to the previous `; ` only, so no byte is read twice.
    let mut floor = 0;
    folded.match_indices("; ").filter_map(move |(at, _)| {
        let attribute = &folded[at + 2..];
        let (floor, end) = (std::mem::replace(&mut floor, map[at]), map[at]);
        if !COOKIE_ATTRIBUTES
            .split(' ')
            .any(|a| attribute.starts_with(a))
        {
            return None;
        }
        let blank = text[floor..end]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace());
        let from = blank.map_or(floor, |(w, c)| floor + w + c.len_utf8());
        let equals = from + text[from..end].find('=')? + 1;
        (text[equals..end].chars().count() >= 4)
            .then(|| Span::new(EntityKind::Secret, equals, end, 1.0, NAME))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(text: &str) -> Vec<&str> {
        let spans = LabelValueRecognizer::new().analyze(text);
        spans
            .iter()
            .map(|span| &text[span.start..span.end])
            .collect()
    }

    #[test]
    fn a_blood_column_reads_max_rows_and_no_more() {
        let mut text = String::from("id,\"x, y\",blood_type\n");
        for row in 1..=MAX_ROWS + 1 {
            text.push_str(&format!("{row},\"a,\"\"b\"\"\",O+\n"));
        }
        let cells = masked(&text);
        assert_eq!(cells.len(), MAX_ROWS);
        assert!(cells.iter().all(|cell| *cell == "O+"));
        assert!(text.ends_with(&format!("{},\"a,\"\"b\"\"\",O+\n", MAX_ROWS + 1)));
    }

    #[test]
    fn every_lexicon_line_parses_and_folds_to_itself() {
        for line in DATA
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        {
            let label = line.rsplit('\t').next().unwrap();
            assert_eq!(fold(label).0, label, "write {label:?} folded");
        }
        assert!(LEXICON.labels.len() > 150);
    }

    /// ID-LABEL-1: `licence` is a label only when a number word follows it.
    #[test]
    fn a_licence_word_is_a_label_before_a_number_word_only() {
        for (text, value) in [
            ("licence number 12AB34567", "12AB34567"),
            ("Licence No. 12AB34567", "12AB34567"),
            ("License Number: 12AB34567", "12AB34567"),
            ("licence n°12AB34567", "n°12AB34567"),
            ("licence\nnumber: 72BD41385", "72BD41385"),
            ("Purpose: business\nLicence number: 72BD41385", "72BD41385"),
            ("Licence number: 99-99-99", "99-99-99"),
        ] {
            assert_eq!(masked(text), [value], "{text:?}");
        }
        for text in [
            "licence: 2024-10-01",
            "licence 12AB34567",
            "licence notes 12AB34567",
            "licence number is on file",
            "licence number: 2024-10-01",
            "licence no 01/10/2024",
            "the certificate license number 84730249",
            // Seal A round 1: two line breaks, a business word in the same
            // field, a real date in either order.
            "licence\n\nnumber: 72BD41385",
            "Purpose of the business licence number 84730249",
            "licence number: 31-12-99",
            "licence number: 12/31/2024",
            "licence number: 99-12-31",
        ] {
            assert!(masked(text).is_empty(), "{text:?}: {:?}", masked(text));
        }
    }

    #[test]
    fn a_value_after_its_label_is_masked() {
        for (text, value) in [
            ("the password might be G9$rP2zT@qWk", "G9$rP2zT@qWk"),
            ("the password, Sunflower@2025, opens it", "Sunflower@2025"),
            ("I changed my pin to 619036 yesterday", "619036"),
            ("**api\\_key**: Zq9Lm2Xv8Rt4Wp7N", "Zq9Lm2Xv8Rt4Wp7N"),
            ("password: 'red horse' ok", "red horse"),
            ("Patient MRN 448812 was admitted.", "448812"),
            ("Personalausweis-Nr. L01X00T47", "L01X00T47"),
            ("| Tax ID   |   98-7654321 |", "98-7654321"),
            ("CNI : 1234 5678 9012 ok", "1234 5678 9012"),
            ("Her blood type is A positive.", "A positive"),
            ("Blood group: AB+", "AB+"),
            ("Blood type: O", "O"),
            ("The patient's blood type is AB-.", "AB-"),
            ("Blood group: AB Rh-", "AB Rh-"),
            ("a blood type of O+ and", "O+"),
            ("mon groupe sanguin c'est A- en fait", "A-"),
            ("medical record number for this donor is 0008811", "0008811"),
            (
                "member ID: QHX81402277 from the health insurer",
                "QHX81402277",
            ),
            ("Numéro de dossier médical : DM-2024-77812", "DM-2024-77812"),
            ("血型：A型Rh阴性", "A型Rh阴性"),
            ("密码是abc12345", "abc12345"),
            ("csrftoken=Ab12Cd34Ef; Path=/", "Ab12Cd34Ef"),
            ("\"password\": \"hunter22\"", "hunter22"),
        ] {
            assert!(
                masked(text).contains(&value),
                "{text:?}: {:?}",
                masked(text)
            );
        }
    }

    /// ID-LABEL-2: the label forms main read one value and left the next in
    /// clear.
    #[test]
    fn a_glued_number_sign_a_spaced_passport_and_a_paren_key_are_read() {
        for (text, value) in [
            ("Numéro de permis de conduire : 12AB34567", "12AB34567"),
            ("N° de permis de conduire : 12AB34567", "12AB34567"),
            ("NUMERO DE PERMIS DE CONDUIRE : 12AB34567", "12AB34567"),
            ("Numéro de permis de conduire:\n12AB34567", "12AB34567"),
            ("numéro de permis de conduire n°12AB34567", "n°12AB34567"),
            ("N° de permis n°12AB34567", "n°12AB34567"),
            ("numéro de permis n°071234567890", "n°071234567890"),
            ("护照号：E 1234 5678", "E 1234 5678"),
            ("passport no: EA 1234 5678", "EA 1234 5678"),
            ("passport number is E 1234 5678", "E 1234 5678"),
            (
                "driver_license_number (D37-4519-8820-41)",
                "D37-4519-8820-41",
            ),
            (
                "{\"driving_license_number\": \"(D37-4519-8820-41)\"}",
                "D37-4519-8820-41",
            ),
            (
                "driver licence number (MORGA-753116-SM9IJ)",
                "MORGA-753116-SM9IJ",
            ),
        ] {
            assert!(
                masked(text).contains(&value),
                "{text:?}: {:?}",
                masked(text)
            );
        }
    }

    /// ID-LABEL-2 round 1: a glued sign's own letters are alphanumerics of the
    /// value, so `no1234` reads exactly as it reads on main.
    #[test]
    fn a_glued_signs_letters_count_toward_the_minimum() {
        for (text, value) in [
            ("tax id no1234", "no1234"),
            ("passport NO123", "NO123"),
            ("medical record number no123", "no123"),
            ("member ID no123 at the health insurer", "no123"),
            ("NHS number: no12", "no12"),
            ("Tax ID: no12", ""),
        ] {
            let spans: Vec<_> = masked(text);
            if value.is_empty() {
                assert!(spans.is_empty(), "{text:?}: {spans:?}");
            } else {
                assert!(spans.contains(&value), "{text:?}: {spans:?}");
            }
        }
        // A sign main cannot read past keeps the head's own reading, and its
        // `n` counts toward the minimum length too.
        assert_eq!(masked("N° de permis n°1234"), ["n°1234"]);
        assert_eq!(masked("N° de permis n°123"), Vec::<&str>::new());
        assert_eq!(masked("tax id nothing12"), ["nothing12"]);
    }

    /// ID-LABEL-2 round 1: `(` is decoration for an ID or a health label only.
    /// Behind a secret label it is the first byte of the value.
    #[test]
    fn an_open_paren_is_decoration_for_a_wide_label_only() {
        for (text, value) in [
            (
                "driver_license_number (D37-4519-8820-41)",
                "D37-4519-8820-41",
            ),
            ("tax id (no1234)", "no1234"),
            ("api_key (smith-404135-zt7jh)", "(smith-404135-zt7jh"),
            ("api_key (smith\r\n404135-zt7jh", "(smith"),
            ("api_key\t(JQA028344)", "(JQA028344"),
            ("password (hunter22)", "(hunter22"),
        ] {
            assert!(
                masked(text).contains(&value),
                "{text:?}: {:?}",
                masked(text)
            );
        }
        // `[secret removed]` still guards a wide label's value; behind a secret
        // label the `(` is read with the token, exactly as on main.
        assert!(masked("driver_license_number ([secret removed])").is_empty());
        assert!(masked("passport ([secret removed])").is_empty());
        assert_eq!(masked("api_key ([secret removed])"), ["([secret"]);
        assert_eq!(masked("password ([secret removed])"), ["([secret"]);
    }

    /// ID-LABEL-2 round 1: a spaced CN passport is read behind a passport label
    /// only.
    #[test]
    fn a_spaced_passport_needs_a_passport_label() {
        for (text, value) in [
            ("passport no: E 1234 5678", "E 1234 5678"),
            ("护照号：E 1234 5678", "E 1234 5678"),
            ("tax id: E 1234 5678", ""),
            ("CNI: E 1234 5678", ""),
            ("driver licence number: E 1234 5678", ""),
        ] {
            let spans = masked(text);
            if value.is_empty() {
                assert!(spans.is_empty(), "{text:?}: {spans:?}");
            } else {
                assert!(spans.contains(&value), "{text:?}: {spans:?}");
            }
        }
    }

    #[test]
    fn a_label_without_a_value_masks_nothing() {
        for text in [
            "spinning 12345678",
            "health plan 2024",
            "password: ⟦SECRET_0123456789AB⟧ and pin [secret removed]",
            "passport\n\n\nAB1234567",
            "<input type=\"password\" id=\"pin\" name=\"pin\" required>",
            "<title>PIN Entry</title> Select 'Change PIN'. 4. Enter",
            "portal/pin-login](https://x.org/pin-login)",
            "| Authentication | Session | https://ico.org.uk |",
            "the certificate license number 84730249",
            "gym member ID 44120098",
            "His health is fine; gym member ID 55120934.",
            "loyalty member number 7712-0093",
            "medical record number for each patient is required",
            "the medical record number for 2024",
            "the password of user123 expired",
            // ID-LABEL-2: a label, and no value behind it.
            "Numéro de permis de conduire à renouveler",
            "N° de permis : à préciser",
            "permis n°",
            "driver_license_number is empty",
            "driver license number (to be confirmed)",
            "passport no: E 1234",
            "passport no: E 12345 6789",
            "passport no: EXY 1234 5678",
            "N° de permis n° rien",
        ] {
            assert!(masked(text).is_empty(), "{text:?}: {:?}", masked(text));
        }
    }

    #[test]
    fn utf8_edges_never_panic() {
        for text in [
            "pin ⟦",
            "密码",
            "password: é",
            "blood type: O\u{301}",
            "MRN 12\u{0}",
            "; path=",
        ] {
            let _ = masked(text);
        }
        let long = format!("password: {}", "é1".repeat(300));
        assert!(!masked(&long).is_empty());
    }
}
