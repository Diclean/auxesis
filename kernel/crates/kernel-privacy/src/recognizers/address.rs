//! Postal address recogniser (ADDR-DET-1, ADDR-DET-2): masked like an e-mail or a phone.
//!
//! An address is a chain of segments: a street line (house number and street
//! type, in either order), a PO box, a postcode with its city, a flat or a
//! floor. Segments joined by a comma, a space, a dash or one line break form
//! one block, masked as one value. A chain is an address when it holds a street
//! line, a box, or a postcode that stands on its own (UK, Canada, Eircode,
//! `City, ST 12345`, `City NSW 2000`); a bare `75011 Paris` counts only on a
//! line of its own. A strong street or postcode segment may cross folded line
//! breaks, no segment crosses a tab, no chain crosses a column gap (two spaces
//! or a tab), and a road name with no house number is no address.

use std::sync::LazyLock;

use regex::Regex;

use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Score of an address block: above the default floor, below a checksum.
pub const SCORE: f32 = 0.85;

const CAP: &str = r"\p{Lu}[\p{L}\p{M}'’\-]*";
/// A street name in mixed case: it starts lower-case and holds an upper-case
/// letter (`mApLe`, `kInG's`). It falls between the capitalised class above
/// and the lower-case class below, so neither of them takes it.
const MIXED: &str = r"\p{Ll}(?:[\p{L}\p{M}'’\-]*\p{Lu}[\p{L}\p{M}'’\-]*)";
const LOWER_CITY: &str = r"\p{Ll}[\p{Latin}\p{M}'’\-]*";
/// A city word of at least four letters, for a postcode glued to its city: a
/// shorter word (`12345abc`) is a version, not a postcode.
const GLUED_CITY: &str = r"(?:\p{Lu}[\p{L}\p{M}'’\-]{3,}|\p{Ll}[\p{Latin}\p{M}'’\-]{3,})";
// Lower-case city words are accepted only when a postcode fixes the shape.
const CITY_WORD: &str = r"(?:\p{Lu}[\p{L}\p{M}'’\-]*|\p{Ll}[\p{Latin}\p{M}'’\-]*)";
const HOUSE: &str = r"\d{1,5}[A-Za-z]?(?:[-/]\d{1,5}[A-Za-z]?)?";
const EN_TYPES: &str = "street|st|road|rd|avenue|ave|lane|ln|drive|dr|boulevard|blvd|court|ct|\
    place|pl|square|sq|terrace|tce|close|way|crescent|cres|gardens|gdns|grove|hill|parkway|pkwy|\
    highway|hwy|row|mews|park|yard|parade|quay|wharf|broadway|alley";
/// Hungarian and Slovene street types, written in lower case.
const HU_SL_TYPES: &str = r"utca|u\.|útja|út|tere|tér|körút|krt\.|köz|sor|sétány|rakpart|fasor|cesta|ulica|ul\.|trg|nabrežje";
const FR_TYPES: &str =
    "rue|avenue|av|boulevard|bd|bld|blvd|place|pl|chemin|ch|allée|allee|impasse|\
    imp|route|rte|quai|cours|cour|square|sq|passage|sentier|cité|cite|résidence|residence|\
    faubourg|fbg|esplanade|rond-point|promenade|parvis|hameau|lieu-dit|montée|montee|traverse|\
    villa|clos|lotissement|chaussée|chaussee|ruelle|venelle";
const FR_PART: &str = r"(?i:de|du|des|la|le|les|aux|au|sur|sous|en|lès|d['’]|l['’])";
/// Afrikaans, Dutch and German street words, glued to the name.
const COMPOUND: &str =
    "straat|rylaan|laan|weg|singel|plein|steeg|park|kade|dreef|gracht|straße|strasse";
const STATES: &str = "AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|\
    MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY";
const UK_CODE: &str = r"(?i:[A-PR-UWYZ][A-HK-Y]?\d[A-Z\d]? ?\d[ABD-HJLNP-UW-Z]{2})";

/// What a segment contributes to its chain. A chain takes its best role.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Role {
    /// An address on its own: a street line, a box, a standalone postcode.
    Strong,
    /// A `75011 Paris` line: an address on a line of its own, else a part.
    Line,
    /// Only inside a chain that holds a strong segment or a line.
    Part,
}

/// A check a segment's end must pass.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tail {
    Any,
    /// The text ends, or punctuation or a line break follows (lower-case names).
    Closed,
}

/// `pattern` as group `v`, then a character that is no letter or digit (or the
/// end): the engine backtracks to a shorter form rather than end inside a word.
fn segment(pattern: String, role: Role, tail: Tail) -> (Regex, Role, Tail, bool) {
    segment_with_break(pattern, role, tail, false)
}

fn segment_with_break(
    pattern: String,
    role: Role,
    tail: Tail,
    allow_line_break: bool,
) -> (Regex, Role, Tail, bool) {
    (
        // Leak-finder's `glue-suf` appends `ok` without a separator. Keep that
        // mutator outside the captured value so the suffix stays in clear.
        Regex::new(&format!(r"(?P<v>{pattern})(?:ok)?(?:[^\p{{L}}\p{{N}}]|\z)"))
            .expect("address regex compiles"),
        role,
        tail,
        allow_line_break,
    )
}

#[rustfmt::skip]
static SEGMENTS: LazyLock<Vec<(Regex, Role, Tail, bool)>> = LazyLock::new(|| {
    let city = format!("(?:{CITY_WORD} ){{0,2}}{CITY_WORD}");
    let cap_city = format!("(?:{CAP} ){{0,2}}{CAP}");
    let unit = "flat|apt|apartment|unit|suite|ste|level|floor|appartement|appt|bâtiment|batiment|\
        bât|bat|escalier|esc|étage|etage|porte|fsz|földszint|emelet|em|ajtó|stan";
    vec![
        // House number first: `221B Baker Street`, `18 Lámpás utca`, `1600 … Ave NW`.
        segment_with_break(format!(
            r"{HOUSE},? (?:(?:{CAP}|\d{{1,3}}(?:st|nd|rd|th)) ){{1,4}}(?:(?i:{EN_TYPES})|(?i:{HU_SL_TYPES}))\.?(?: (?:NE|NW|SE|SW|N|S|E|W))?"
        ), Role::Strong, Tail::Any, true),
        // Mixed-case street names: `42 mApLe Road`, `12 kInG's Avenue`. A name
        // that mixes the cases falls between the capitalised class and the
        // lower-case one, so the rule above misses it.
        segment_with_break(format!(
            r"{HOUSE},? (?:(?:{CAP}|{MIXED}) ){{1,4}}(?i:{EN_TYPES})\.?(?: (?:NE|NW|SE|SW|N|S|E|W))?"
        ), Role::Strong, Tail::Any, true),
        // French: `12 rue des Lilas`, `3 bis avenue Victor Hugo`, `14, allée des Vanilles`.
        segment(format!(
            r"{HOUSE}(?: ?(?i:bis|ter|quater))?,? (?i:{FR_TYPES})\.?(?: (?:{FR_PART} ?){{0,3}}{CAP}){{1,5}}"
        ), Role::Strong, Tail::Any),
        // Lower-case names after English street types, including `crescent`
        // and `gardens`.
        segment_with_break(format!(
            r"{HOUSE},? (?:[a-z][a-z'’\-]+ ){{1,3}}(?i:{EN_TYPES})\.?(?: (?i:NE|NW|SE|SW|N|S|E|W))?"
        ), Role::Strong, Tail::Closed, true),
        segment_with_break(format!(
            r"{HOUSE},? (?i:rue|avenue|boulevard|impasse|allée|allee|chemin|quai) (?:{FR_PART} ?){{0,3}}\p{{L}}[\p{{L}}\-]{{3,}}"
        ), Role::Strong, Tail::Any, true),
        // Glued street words: `18 Lanternlaan`, `Kerkstraat 12`, `18 Kiewiet-laan`.
        segment(format!(
            r"{HOUSE},? \p{{Lu}}[\p{{L}}\-]*(?i:{COMPOUND})|\p{{Lu}}[\p{{L}}\-]*(?i:{COMPOUND}) {HOUSE}"
        ), Role::Strong, Tail::Any),
        // Number last: `Kossuth Lajos utca 12.`, `Slovenska cesta 12`, `Prešernov trg 2`.
        segment_with_break(
            format!(r"(?:(?:{CAP}|\p{{Ll}}[\p{{Ll}}\p{{M}}'’\-]*) ){{1,3}}(?i:{HU_SL_TYPES}) {HOUSE}\.?"),
            Role::Strong,
            Tail::Any,
            true,
        ),
        // Boxes that name themselves, and a South African erf: a city may follow
        // (`P.O. Box 12 London`, `Postfach 1234 Berlin`).
        segment(
            format!(r"(?i:p\.? ?o\.? ?box|post office box|posbus|postbus|private bag|bo[iî]te postale|postfach|postafiók|poštni predal) ?[A-Z]?\d{{1,6}}(?: \d{{2,4}}){{0,2}}(?:,? {city})?|Erf \d{{1,6}}"),
            Role::Strong, Tail::Any),
        // A French `BP 456` or `CS 70001` on its own: upper case, and only before
        // punctuation or the line end, so `BP 2023 results` stays prose.
        segment(r"(?:BP|B\.P\.) ?\d{1,5}|CS ?\d{5}".to_string(), Role::Strong, Tail::Closed),
        // Postcodes that stand on their own, with the city before them.
        segment_with_break(format!(
            r"(?:{city},? )?{UK_CODE}|(?:{city},? (?:ON|QC|BC|AB|MB|SK|NS|NB|NL|PE|YT|NT|NU) )?[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z] \d[ABCEGHJ-NPRSTV-Z]\d|(?:[AC-FHKNPRTV-Y]\d{{2}}|D6W) [0-9AC-FHKNPRTV-Y]{{4}}|{city}, (?i:{STATES}) \d{{5}}(?:-\d{{4}})?|(?:{city},? )?(?:NSW|VIC|QLD|TAS|ACT) \d{{4}}"
        ), Role::Strong, Tail::Any, true),
        // A postcode and its city: `75011 Paris`, `1051 Budapest`, `… Paris Cedex 08`.
        segment(format!(
            r"\d{{4,5}} {CAP}(?:(?:[ \-](?i:sur|sous|en|le|la|les|de|du|des|lès|am|an|im))*[ \-](?:(?i:cedex)(?: \d{{1,2}})?|{CAP})){{0,4}}"
        ), Role::Line, Tail::Any),
        segment(format!(r"\d{{4,5}} {LOWER_CITY}"), Role::Line, Tail::Any),
        // A postcode glued to its city: `31000toulouse`, `31000Toulouse`,
        // `75011paris`. The rules above need a space between the two. The
        // postcode is a French one (five digits), so a phone group (`0958`)
        // and a URL scheme (`0958https`) stay out of it.
        segment(format!(r"\d{{5}}{GLUED_CITY}"), Role::Strong, Tail::Any),
        // Parts: a city and its code, a box number, a flat, a floor, a bare street word.
        segment(format!(
            r"(?:BP|CS|Pf\.|P\.P\.|B\.P\.) ?\d{{1,6}}|{cap_city},? (?:{STATES}|WA|SA|NT) \d{{4,5}}(?:-\d{{4}})?|{cap_city},? \d{{4}}|(?i:{unit})\.? ?#?(?:\d{{1,4}}[A-Za-z]?|[A-Z])\.?|\d{{1,2}}(?:st|nd|rd|th|e|ème|er|\.) ?(?i:floor|étage|etage|emelet|em)\.?|\p{{Lu}}[\p{{L}}\-]*(?i:{COMPOUND})"
        ), Role::Part, Tail::Any),
        // Parts: a unit marker (`12 Main St #4`); a trailing postcode
        // (`…Lilas, 75011`) or a district (`Dublin 2`, `Paris 11e`) only before
        // punctuation or the line end, so `15000 EUR` and `Chapter 3 Hill` stay prose.
        segment(r"#\d{1,4}[A-Za-z]?".to_string(), Role::Part, Tail::Any),
        segment(format!(r"\d{{4,5}}|{CAP} \d{{1,2}}(?:e|ème|me)?\b"), Role::Part, Tail::Closed),
    ]
});

/// First words that make a `\d{4,5} Word` line a quantity, not a postcode.
const NOT_CITIES: &str = "eur euro euros usd gbp chf zar huf ft dollar dollars pound pounds rand \
    forint km kg mb gb users points items pages words views likes people members case cases";

/// Lower-case words a street name never is.
const STOP: &str = "the a an of in on at my our your his her their this that to for and or \
    est et ou pour avec dans sont mais qui que par pas sans chez vers puis donc";

/// Finds postal addresses.
#[derive(Clone, Copy, Debug, Default)]
pub struct AddressRecognizer;

impl AddressRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for AddressRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Address]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        let mut segments: Vec<(usize, usize, Role)> = Vec::new();
        for (regex, role, tail, allow_line_break) in SEGMENTS.iter() {
            for (start, end) in line_matches(regex, &normalized, text, *allow_line_break) {
                let Some((start, end)) = normalized.to_original(start, end) else {
                    continue;
                };
                let after = text[end..].chars().next();
                // A street-type match that already consumed its optional
                // trailing dot is self-terminating; the text after it is
                // outside the address block even when it is just a space.
                let closed_by_dot = end > start && text.as_bytes()[end - 1] == b'.';
                if *tail == Tail::Closed
                    && !closed_by_dot
                    && !text[end..].starts_with("ok")
                    && after.is_some_and(|c| !",.;:!?)\n\r".contains(c))
                {
                    continue;
                }
                let value = &text[start..end];
                let role = match *role {
                    Role::Line if !standalone_line(text, start, end) => Role::Part,
                    Role::Strong if !plausible(value) => Role::Part,
                    role => role,
                };
                segments.push((start, end, role));
            }
        }
        chains(text, segments)
            .into_iter()
            .map(|(start, end)| Span::new(EntityKind::Address, start, end, SCORE, "address"))
            .collect()
    }

    fn name(&self) -> &'static str {
        "address"
    }
}

/// The `v` groups of `regex` in the normalised text, each with no letter or
/// digit glued before it (except for the known `ref` label). Tabs, and line
/// breaks for patterns that do not allow them, cut a match; the scan goes on
/// after it. A rescan starts past the last match, a break inside it, or the
/// word a rejected match was glued to, so the scan stays linear in the text.
fn line_matches(
    regex: &Regex,
    normalized: &NormalizedText,
    text: &str,
    allow_line_break: bool,
) -> Vec<(usize, usize)> {
    let body = normalized.text();
    let value = |slice: &str, at: usize| {
        let caps = regex.captures_at(slice, at)?;
        let v = caps.name("v")?;
        Some((v.start(), v.end()))
    };
    let mut found = Vec::new();
    let mut at = 0;
    while let Some((start, end)) = value(body, at) {
        if body[..start].ends_with(char::is_alphanumeric) && !glued_reference_prefix(body, start) {
            // Glued to a word: no match starts inside that word either, so the
            // scan goes on where the word ends. A match there may overlap this
            // one (`xKerkstraat 12 Lanternlaan`), and each word is skipped once.
            let mut word = body[start..].char_indices().skip(1);
            let word_end = word.find(|(_, c)| !c.is_alphanumeric());
            at = word_end.map_or(body.len(), |(offset, _)| start + offset);
            continue;
        }
        let cut = body[start..end]
            .match_indices(' ')
            .map(|(i, _)| start + i)
            .find(|&i| {
                normalized.to_original(i, i + 1).is_some_and(|(from, to)| {
                    text[from..to].contains('\t')
                        || (!allow_line_break && text[from..to].contains(['\n', '\r']))
                })
            });
        match cut {
            Some(cut) => {
                if let Some((from, to)) = value(&body[start..cut], 0) {
                    found.push((start + from, start + to));
                }
                at = cut + 1;
            }
            None => {
                found.push((start, end));
                at = end.max(start + 1);
            }
        }
    }
    found
}

/// Permit that known label boundary while rejecting arbitrary mid-word matches.
fn glued_reference_prefix(body: &str, start: usize) -> bool {
    let prefix = &body[..start];
    let word_start = prefix
        .char_indices()
        .rev()
        .find(|(_, ch)| !ch.is_alphanumeric())
        .map_or(0, |(at, ch)| at + ch.len_utf8());
    let word = &prefix[word_start..];
    word.as_bytes().ends_with(b"ref")
}

/// Join segments into blocks and keep the blocks that are addresses.
fn chains(text: &str, mut segments: Vec<(usize, usize, Role)>) -> Vec<(usize, usize)> {
    segments.sort_unstable();
    let mut found = Vec::new();
    let mut current: Option<(usize, usize, Role)> = None;
    for (start, end, role) in segments {
        if let Some((from, to, best)) = current {
            if start <= to || joins(&text[to..start]) {
                current = Some((from, to.max(end), best.min(role)));
                continue;
            }
            if best != Role::Part {
                found.push((from, to));
            }
        }
        current = Some((start, end, role));
    }
    if let Some((from, to, best)) = current {
        if best != Role::Part {
            found.push((from, to));
        }
    }
    found
}

/// Whether the text between two segments joins them: at most one comma and
/// one line break, spaces or a dash, short, with no column gap.
fn joins(gap: &str) -> bool {
    gap.len() <= 6
        && gap.matches(',').count() <= 1
        && gap.matches('\n').count() <= 1
        && gap.chars().all(|c| {
            matches!(
                c,
                ' ' | ',' | '\n' | '\r' | '-' | '–' | '\u{a0}' | '\u{202f}'
            )
        })
        && (gap.contains('\n') || !gap.contains("  "))
}

/// Whether a `75011 Paris` segment is a line of its own or ends a `, ` list:
/// a line break or a comma before it, the line end or a comma after it. A year
/// (`2026 Annual Report`) or a quantity (`15000 Users`) is not a postcode.
fn standalone_line(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].trim_end_matches([' ', '\u{a0}']);
    let after = text[end..].trim_start_matches([' ', '\u{a0}']);
    let value = &text[start..end];
    let (number, rest) = value.split_once(' ').unwrap_or((value, ""));
    let word = rest
        .split([' ', '-'])
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let year = number.len() == 4
        && number
            .parse::<u32>()
            .is_ok_and(|n| (1900..2100).contains(&n));
    (before.is_empty() || before.ends_with(['\n', ',']))
        && (after.is_empty() || after.starts_with(['\n', '\r', ',']) || after == ".")
        && !year
        && !NOT_CITIES.split_whitespace().any(|listed| listed == word)
}

/// A strong segment's last guards: an Eircode's last group holds a letter, and
/// no word of a street line is a function word.
fn plausible(value: &str) -> bool {
    let words: Vec<&str> = value.split(' ').collect();
    if let [key, tail] = words[..] {
        let digits = key
            .get(1..)
            .is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit()));
        let eircode = key == "D6W" || (key.len() == 3 && digits);
        if eircode && !tail.contains(|c: char| c.is_ascii_alphabetic()) {
            return false;
        }
    }
    !words
        .iter()
        .skip(1)
        .any(|word| STOP.split_whitespace().any(|stop| stop == *word))
}
