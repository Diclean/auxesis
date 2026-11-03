//! UK National Insurance number recogniser (`AB 12 34 56 C` or `AB123456C`).

use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// The name echoed in [`Span::recognizer`].
const NAME: &str = "uk_nino";

/// A National Insurance number, with no checksum: two letters, six digits and a
/// suffix letter A to D. Each pair boundary may hold one space or hyphen, in any
/// mix. It runs on the normalised view, so NBSP and fullwidth forms fold first.
/// A number starts only where no ASCII letter or digit precedes it — except on
/// the offsets a number just read left open ([`opens_another`]) — and ends only
/// where none follows; an underscore or a combining mark is no part of it.
/// Every such start is tried on its own, so a rejected shape never hides the
/// number after it, and each try reads at most thirteen bytes (linear scan).
///
/// A suffix letter glued to a following letter or digit is refused, unless a
/// number's shape starts at that letter, a pass reads another number within
/// three bytes behind it ([`read_near`], NINO-CHAIN r2), or a line break sits
/// before it. In the first case the
/// letter is kept and the caller reads the next number from there as well
/// (NINO-CHAIN): where that number starts at the letter, the two spans overlap
/// and [`union`] makes them one, so neither number gives a byte to the other
/// (`AB 12 34 56\ncb123456a` left its head in clear: this rule refused it, and
/// the FIN-6 cut needs capitals). In the second, the letter opens the next line,
/// so it is masked with this number, which makes the next line a word again, so
/// its label still matches and the value behind it stays masked
/// (NINO-GLUED-NEXT).
///
/// A whole number at that letter that no pass reads on its own (its suffix is
/// glued to an IBAN or a key) is read with this one, to its own suffix
/// ([`glued_next_end`], NINO-CHAIN r1): taking only its first letter left
/// `l 05 51 39 d` in clear in `ak 67 18 39\r\nbl 05 51 39 dGB82…`, where main
/// left the letter to the residue round. Open mode has no residue round, so
/// the chain is read whole in the first.
fn nino_at(
    bytes: &[u8],
    start: usize,
    text: &str,
    view: &NormalizedText,
    reads: &[bool],
) -> Option<usize> {
    let separator = |index: usize| matches!(bytes.get(index), Some(b' ' | b'-'));
    let mut index = head_at(bytes, start)?;
    let (before, spaced) = (index, separator(index));
    index += usize::from(spaced);
    let suffix = index;
    if !matches!(bytes.get(index), Some(b'A'..=b'D' | b'a'..=b'd')) {
        return None;
    }
    index += 1;
    if bytes.get(index).is_some_and(u8::is_ascii_alphanumeric) {
        if let Some(next) = glued_next_end(bytes, suffix, reads) {
            return Some(next);
        }
        let near = number_starts_at(bytes, suffix) || read_near(reads, suffix).is_some();
        if !near && !(spaced && broke_line(text, view, before)) {
            return None;
        }
    }
    Some(index)
}

/// The offset one past the suffix letter of a whole number — prefix, six
/// digits and a suffix letter A to D — that starts at `at` where no pass reads
/// it on its own: its suffix is glued to a value (an IBAN, a key). The number
/// whose suffix letter is its first letter reads it with itself (NINO-CHAIN
/// r1): a chain is evidence of its own. A shape with no suffix letter is no
/// number in any round, so the number before it keeps only the letter, as on
/// main. At most thirty-four bytes.
fn glued_next_end(bytes: &[u8], at: usize, reads: &[bool]) -> Option<usize> {
    if read_at(reads, at) {
        return None;
    }
    let compact = head_at(bytes, at).and_then(|end| {
        let end = end + usize::from(matches!(bytes.get(end), Some(b' ' | b'-')));
        matches!(bytes.get(end), Some(b'A'..=b'D' | b'a'..=b'd')).then_some(end + 1)
    });
    compact.max(separated_shape_at(bytes, at).map(|shape| shape.end))
}

/// Whether a pass reads a National Insurance number at `at` ([`nino_at`] or
/// [`separated_nino_at`], start rule waived), from the table [`reads_table`]
/// fills. `false` past the end.
fn read_at(reads: &[bool], at: usize) -> bool {
    reads.get(at).copied().unwrap_or(false)
}

/// The first offset from `at` to `at + 3` where a pass reads a National
/// Insurance number: the suffix letter of the number before it, or one of the
/// three bytes behind it (`AB 12 34 56\nBAB…`, `AB123456CXAB…`). One window for
/// both places that ask (NINO-CHAIN): the glue rule of [`nino_at`] and
/// [`opens_another`]. Four table reads.
fn read_near(reads: &[bool], at: usize) -> Option<usize> {
    (0..=3)
        .map(|step| at + step)
        .find(|&offset| read_at(reads, offset))
}

/// For every offset, whether a pass reads a number there (NINO-CHAIN r1). A
/// number's glue rule asks only about offsets at least eight bytes behind its
/// start, so one walk from the end fills the table with no recursion: a chain
/// of any length costs one try per offset, and each try reads at most
/// twenty-one bytes (linear scan). Only offsets where a number's shape starts
/// are tried at all.
fn reads_table(bytes: &[u8], text: &str, view: &NormalizedText) -> Vec<bool> {
    let mut reads = vec![false; bytes.len()];
    for at in (0..bytes.len()).rev() {
        if number_starts_at(bytes, at) {
            reads[at] = nino_at(bytes, at, text, view, &reads).is_some()
                || separated_nino_at(bytes, at, text, view, &reads).is_some();
        }
    }
    reads
}

/// Where the next number may start after a number that ended at `end`: one that
/// kept its suffix letter looks from that letter on ([`read_near`]); one the
/// FIN-6 cut ended before the letter looks at the letter. `None` when no pass
/// reads a number there.
///
/// A letter or digit may precede that offset, and [`analyze`] waives its start
/// rule there and reads from it even inside the span just read (NINO-CHAIN):
/// the letter is shared by both numbers, so a start rule that read the whole
/// word, or a scan that went on past the span, left the next number in clear
/// (`AB 12 34 56\nBAB123456B`, the middle of `XY 12 34 56 AB 12 34 56 AB …`).
fn opens_another(bytes: &[u8], end: usize, reads: &[bool]) -> Option<usize> {
    let last = end.checked_sub(1)?;
    if bytes[last].is_ascii_alphabetic() {
        read_near(reads, last)
    } else {
        read_at(reads, end).then_some(end)
    }
}

/// The offset one past the six digits of a National Insurance number that starts
/// at `start`: two prefix letters HMRC can issue, then three pairs of digits
/// with at most one space or hyphen at each boundary. No suffix letter, so this
/// also reads a number whose own suffix is glued to a value, which only the
/// residue round sees whole (NINO-GLUED-NEXT). At most eleven bytes (linear
/// scan).
fn head_at(bytes: &[u8], start: usize) -> Option<usize> {
    let letter = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_alphabetic);
    let digit = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_digit);
    if !(letter(start) && letter(start + 1)) || !prefix_allowed(bytes[start], bytes[start + 1]) {
        return None;
    }
    let mut index = start + 2;
    for _ in 0..3 {
        if matches!(bytes.get(index), Some(b' ' | b'-')) {
            index += 1;
        }
        if !(digit(index) && digit(index + 1)) {
            return None;
        }
        index += 2;
    }
    Some(index)
}

/// Whether the normalised separator at `index` came from a run that held a line
/// break in `text`. One binary search per call, so a scan stays
/// linear-logarithmic in the length of its input. Read only where a suffix
/// letter is glued to a following letter (NINO-NEWLINE-SUFFIX).
fn broke_line(text: &str, view: &NormalizedText, index: usize) -> bool {
    view.to_original(index, index + 1)
        .is_some_and(|(start, end)| crate::normalize::holds_line_break(&text[start..end]))
}

/// Whether a National Insurance number starts at `at`, in every shape this file
/// reads: the compact and single-separator shapes of [`head_at`] and the FIN-6
/// separated shapes of [`separated_shape_at`] (one to three spaces, or one `-`,
/// `/` or `.`, in any case). One predicate for the one question the glue rule
/// asks, so the suffix letter is kept only where the residue round really will
/// read a number from it.
///
/// It must be a superset of what either pass reads there, never a subset: a
/// second pattern list that read only single spaces and hyphens let the suffix
/// swallow the first letter of every other shape, and the number behind that
/// letter was then no number at all and stood in clear (NINO-GLUED-NEXT r1,
/// `AB 12 34 56\nCB/12/34/56/A`). So neither rule on what *follows* a number —
/// the digit glued to its suffix, the capitals FIN-6 asks for — is applied here.
/// Both only narrow what a pass reads, and narrowing here would eat a letter
/// that opens a line some pass still reads. At most twenty-one bytes per try
/// (linear scan), and it is only reached where a suffix is already glued.
fn number_starts_at(bytes: &[u8], at: usize) -> bool {
    head_at(bytes, at).is_some() || separated_shape_at(bytes, at).is_some()
}

/// What a FIN-6 separated shape reads at one offset, before any rule on what
/// follows its suffix letter: the two prefix letters, the suffix letter with the
/// offset one past it, and the offset where the separator run that precedes the
/// suffix begins — a line break inside that run puts whatever follows the suffix
/// on the next line.
struct Separated {
    first: u8,
    second: u8,
    suffix: usize,
    end: usize,
    last: usize,
}

/// FIN-6: the shape of a number whose four pair boundaries hold the same
/// separator: one to three spaces, or one `-`, `/` or `.` (`PN/48/15/16/C`,
/// `PN  48  15  16  C`, `CB 12  34 56 A`), with a suffix letter A to D. The
/// shape alone, which is what the glue rule asks about
/// ([`number_starts_at`]) and what [`separated_nino_at`] then judges. Each try
/// reads at most twenty-one bytes (linear scan).
fn separated_shape_at(bytes: &[u8], start: usize) -> Option<Separated> {
    let (first, second) = (*bytes.get(start)?, *bytes.get(start + 1)?);
    if !(first.is_ascii_alphabetic() && second.is_ascii_alphabetic())
        || !prefix_allowed(first, second)
    {
        return None;
    }
    let sep = *bytes.get(start + 2)?;
    let most = match sep {
        b' ' => 3,
        b'-' | b'/' | b'.' => 1,
        _ => return None,
    };
    let mut index = start + 2;
    // Where the run that precedes the suffix letter starts.
    let mut last = start + 2;
    for pair in 0..4 {
        let run = bytes[index..]
            .iter()
            .take(most + 1)
            .take_while(|&&b| b == sep);
        let run = run.count();
        if run == 0 || run > most {
            return None;
        }
        last = index;
        index += run;
        if pair < 3 {
            if !bytes.get(index..index + 2)?.iter().all(u8::is_ascii_digit) {
                return None;
            }
            index += 2;
        }
    }
    let suffix = *bytes.get(index)?;
    if !matches!(suffix, b'A'..=b'D' | b'a'..=b'd') {
        return None;
    }
    Some(Separated {
        first,
        second,
        suffix: index,
        end: index + 1,
        last,
    })
}

/// FIN-6: a number whose four pair boundaries hold the same separator. A digit
/// may not touch it. A letter may (`refPN 48 15 16 C`, `PN 48 15 16 Cok`) when
/// the prefix and the suffix are capitals: then the separators still mark it.
/// A suffix letter that opens another number lifts both rules on its side
/// (NINO-CHAIN): the digit before, and the case of a letter after.
/// A suffix glued to a following letter across a line break ends the shape at the
/// break, so the next line is read whole from its own first letter, but only
/// where another number starts there (NINO-GLUED-NEXT): a word the suffix took
/// its first letter from is masked letter and all, which leaves the word a label
/// can match. At most twenty-one bytes (linear scan).
fn separated_nino_at(
    bytes: &[u8],
    start: usize,
    text: &str,
    view: &NormalizedText,
    reads: &[bool],
) -> Option<usize> {
    let Separated {
        first,
        second,
        suffix,
        end,
        last,
    } = separated_shape_at(bytes, start)?;
    let after = bytes.get(end).copied();
    // Its suffix letter opens another number: a chain is evidence of its own,
    // so neither a digit before it nor lower case glued to the next number
    // refuses it (NINO-CHAIN). A value masked before a chain
    // (`…9268 19AB 65  43 21\tCB-87 …`) left its last digit there, and only the
    // residue round read the number behind it, from the next number's letter:
    // masking that letter first left the number in clear. A whole number that
    // no pass reads on its own there (its suffix is glued to an IBAN or a key)
    // is read with this one ([`glued_next_end`], NINO-CHAIN r1).
    let shared = after.is_some_and(|b| b.is_ascii_alphabetic()) && number_starts_at(bytes, suffix);
    let glued_next = shared
        .then(|| glued_next_end(bytes, suffix, reads))
        .flatten();
    if start > 0 && bytes[start - 1].is_ascii_digit() && !shared {
        return None;
    }
    // A line break before the suffix puts what follows on the next line, so a
    // letter or digit glued to it is that line's first character, not this
    // number's (NINO-GLUED-NEXT).
    let next_line = matches!(after, Some(alphanumeric) if alphanumeric.is_ascii_alphanumeric())
        && broke_line(text, view, last);
    if after.is_some_and(|b| b.is_ascii_digit()) && !next_line {
        return None;
    }
    let glued = (start > 0 && bytes[start - 1].is_ascii_alphabetic())
        || (after.is_some_and(|b| b.is_ascii_alphabetic()) && !shared);
    let capitals = [first, second, *bytes.get(suffix)?]
        .iter()
        .all(u8::is_ascii_uppercase);
    if !glued || capitals {
        // The suffix is masked with the number and the next line is read from
        // its second character: a word whose first letter the suffix took is
        // then a word again, so its label still matches and its value stays
        // masked. One exception, and the reason the cut exists: another number
        // starts at that letter, whose own digits must be read whole (FIN-6).
        // `number_starts_at` knows every shape, not only the spaced ones, so
        // the cut lands on all of them (NINO-GLUED-NEXT r1). On one line the
        // letter is kept, and the scan reads the next number from it too
        // ([`opens_another`], NINO-CHAIN), unless no pass reads it there.
        return Some(match glued_next {
            Some(next) => next,
            None if shared && next_line => suffix,
            None => end,
        });
    }
    None
}

/// Whether the two letters of a National Insurance number are a HMRC prefix that
/// can be issued. The first letter is not D, F, I, Q, U or V; the second is not D,
/// F, I, O, Q, U or V; and BG, GB, NK, KN, TN, NT and ZZ are refused. QQ is the
/// HMRC documentation example, and it is masked as a real shape (K13).
fn prefix_allowed(first: u8, second: u8) -> bool {
    let pair = [first.to_ascii_uppercase(), second.to_ascii_uppercase()];
    if &pair == b"QQ" {
        return true;
    }
    !(b"DFIQUV".contains(&pair[0])
        || b"DFIOQUV".contains(&pair[1])
        || matches!(&pair, b"BG" | b"GB" | b"NK" | b"KN" | b"TN" | b"NT" | b"ZZ"))
}

/// Two-letter words a lower-case number glued to a word may not start with:
/// `at 10 20 30 cats` is prose (ID-LABEL-1).
const SHORT_WORDS: &[&[u8; 2]] = &[
    b"ah", b"al", b"am", b"an", b"as", b"at", b"ax", b"ay", b"be", b"by", b"ce", b"eh", b"el",
    b"em", b"en", b"er", b"es", b"et", b"ex", b"ha", b"he", b"hm", b"je", b"la", b"le", b"lo",
    b"ma", b"me", b"my", b"ne", b"oh", b"ok", b"on", b"or", b"ow", b"pa", b"sa", b"se", b"so",
    b"ta", b"te", b"we", b"ya", b"ye", b"yo",
];

/// ID-LABEL-1: the spellings no pass above reads, scanned on the original
/// text with each character read as itself:
///
/// * all in lower case with the suffix glued to a word (`pn 48 15 16 cok`),
///   when the boundaries are blanks or zero-width characters and the prefix is
///   no [`SHORT_WORDS`] word: a dotted or dashed one glued is a host or a path,
///   and `Flight BA 12 34 56 dispatched` is prose;
/// * zero-width characters as separators (`PN\u{200b}48…`), which the
///   normalised view drops, so the number read there is compact and glued;
/// * up to three blank, `.` or `-` characters at a boundary (`PN..48..15..16..C`),
///   the same at all four boundaries (`AB-12-34-56 Cat` is a part number), and
///   `/` single (`//` is a path's);
/// * Cyrillic or Greek capitals that look like the Latin ones (`РΝ 48 15 16 С`),
///   only when all three letters are capitals.
///
/// No letter or digit may precede it and no digit follow it. The span ends at
/// the suffix letter. Each try reads at most twenty-one characters: linear.
fn loose_ninos(text: &str) -> Vec<Span> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    (0..chars.len())
        .filter_map(|at| {
            let end = loose_at(&chars, at)?;
            let end = chars.get(end).map_or(text.len(), |&(byte, _)| byte);
            Some(Span::new(EntityKind::UkNino, chars[at].0, end, 1.0, NAME))
        })
        .collect()
}

/// The char index one past the suffix letter of a [`loose_ninos`] number that
/// starts at char `at`.
fn loose_at(chars: &[(usize, char)], at: usize) -> Option<usize> {
    let ch = |index: usize| chars.get(index).map(|&(_, c)| c);
    if at > 0 && ch(at - 1).is_some_and(char::is_alphanumeric) {
        return None;
    }
    let first = latin_letter(ch(at)?)?;
    let second = latin_letter(ch(at + 1)?)?;
    if !prefix_allowed(first.0, second.0) {
        return None;
    }
    // ID-LABEL-2: after an explicit NI label, a boundary may also be empty or
    // differ from the others (`NI number: Qq284615b`, `NI no: AB  12 34   56 C`).
    let labelled = ni_labelled(chars, at);
    let (mut index, mut blank, mut mark, mut first_run) = (at + 2, true, None, None);
    for pair in 0..4 {
        // Behind a label, up to eight blanks or tabs (`NI number: Qq\t28 …`).
        let max = if labelled { 8 } else { 3 };
        let run = chars[index.min(chars.len())..]
            .iter()
            .take(max + 1)
            .take_while(|&&(_, c)| loose_separator(c).is_some() || (labelled && c == '\t'))
            .count();
        if (run == 0 && !labelled) || run > max {
            return None;
        }
        let this: Vec<char> = chars[index..index + run].iter().map(|&(_, c)| c).collect();
        if first_run.get_or_insert_with(|| this.clone()) != &this && !labelled {
            return None;
        }
        for &c in &this {
            if loose_separator(c) == Some(false) {
                if mark.is_some_and(|m| m != c) || (c == '/' && run > 1) {
                    return None;
                }
                (blank, mark) = (false, Some(c));
            }
        }
        index += run;
        if pair < 3 {
            if !(ch(index).is_some_and(|c| c.is_ascii_digit())
                && ch(index + 1).is_some_and(|c| c.is_ascii_digit()))
            {
                return None;
            }
            index += 2;
        }
    }
    let suffix = latin_letter(ch(index)?)?;
    let after = ch(index + 1);
    if !matches!(suffix.0, b'A'..=b'D') || after.is_some_and(char::is_numeric) {
        return None;
    }
    let letters = [first, second, suffix];
    let capitals = letters.iter().all(|letter| letter.1);
    let lower = letters.iter().all(|letter| !letter.1);
    if letters.iter().any(|letter| letter.2) && !capitals {
        return None;
    }
    let word = [first.0, second.0].map(|b| b.to_ascii_lowercase());
    if after.is_some_and(char::is_alphabetic)
        && !capitals
        && !labelled
        && (!lower || !blank || SHORT_WORDS.contains(&&word))
    {
        return None;
    }
    Some(index + 1)
}

/// Explicit NI labels, folded to lower case: after one, a loose number in
/// mixed case or after a short word, suffix glued, is the value (seal A r1).
const NI_LABELS: &[&str] = &[
    "national insurance number",
    "national insurance no",
    "ni number",
    "ni no",
    "nino",
];

/// Whether an [`NI_LABELS`] label, not glued to a letter or digit before it,
/// ends right before char `at`, past up to twelve blanks, `:`, `#`, `=`, `.`,
/// `,` or `-` with at most one line break among them (ID-LABEL-2: `NI number:\n…`,
/// `NI number:      …`). It reads at most forty characters back: linear.
fn ni_labelled(chars: &[(usize, char)], at: usize) -> bool {
    let run = || {
        chars[..at].iter().rev().take(13).take_while(|&&(_, c)| {
            matches!(
                c,
                ' ' | '\t' | '\u{a0}' | ':' | '#' | '=' | '.' | ',' | '-' | '\r' | '\n'
            )
        })
    };
    let link = run().count();
    if link == 0 || link > 12 || run().filter(|&&(_, c)| c == '\n').count() > 1 {
        return false;
    }
    let end = aside_start(chars, at - link);
    NI_LABELS.iter().any(|label| {
        let len = label.chars().count();
        end >= len
            && chars[end - len..end]
                .iter()
                .map(|&(_, c)| c.to_ascii_lowercase())
                .eq(label.chars())
            && !(end > len && chars[end - len - 1].1.is_alphanumeric())
    })
}

/// Where an NI label ends when one short aside closes right before `end`
/// (`NI number (if applicable): …`, ID-LABEL-2 r1): one to thirty letters,
/// blanks, `'`, `-` or `/` in parentheses, and up to three blanks before them.
/// `end` itself when there is none. At most thirty-five characters back.
fn aside_start(chars: &[(usize, char)], end: usize) -> usize {
    if end == 0 || chars[end - 1].1 != ')' {
        return end;
    }
    let inner = chars[..end - 1]
        .iter()
        .rev()
        .take(31)
        .take_while(|&&(_, c)| c.is_alphabetic() || matches!(c, ' ' | '\'' | '’' | '-' | '/'))
        .count();
    let open = end - 1 - inner;
    if inner == 0 || inner > 30 || open == 0 || chars[open - 1].1 != '(' {
        return end;
    }
    if !chars[open..end - 1].iter().any(|&(_, c)| c.is_alphabetic()) {
        return end;
    }
    let blanks = chars[..open - 1]
        .iter()
        .rev()
        .take(4)
        .take_while(|&&(_, c)| matches!(c, ' ' | '\t'))
        .count();
    if blanks > 3 {
        return end;
    }
    open - 1 - blanks
}

/// `ch` read as a Latin letter: its capital, whether it is written in capitals,
/// and whether it is a Cyrillic or Greek look-alike.
fn latin_letter(ch: char) -> Option<(u8, bool, bool)> {
    if ch.is_ascii_alphabetic() {
        return Some((
            ch.to_ascii_uppercase() as u8,
            ch.is_ascii_uppercase(),
            false,
        ));
    }
    if !(crate::contacts::fold::is_cyrillic(ch) || crate::contacts::fold::is_greek(ch)) {
        return None;
    }
    let mut lower = ch.to_lowercase();
    let single = lower.next().filter(|_| lower.next().is_none());
    let latin = crate::contacts::fold::homoglyph(ch)
        .or_else(|| single.and_then(crate::contacts::fold::homoglyph))?;
    Some((latin.to_ascii_uppercase() as u8, ch.is_uppercase(), true))
}

/// Whether `ch` may stand at a pair boundary, and whether it is a blank or a
/// zero-width character (`Some(true)`) rather than `.`, `-` or `/`.
fn loose_separator(ch: char) -> Option<bool> {
    match ch {
        ' ' | '\u{a0}' | '\u{2009}' | '\u{202f}' => Some(true),
        '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}' => Some(true),
        '.' | '-' | '/' => Some(false),
        _ => None,
    }
}

/// The National Insurance number recogniser.
#[derive(Clone, Copy, Debug)]
pub struct UkNinoRecognizer;

impl UkNinoRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Default for UkNinoRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for UkNinoRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::UkNino]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, false);
        let bytes = normalized.text().as_bytes();
        let mut spans = Vec::new();
        // FIN-6: the separated shapes, then one union of both passes. Neither
        // pass is allowed to lose to the other (NINO-GLUED-NEXT r1): the compact
        // pass eats the suffix letter that opens a line, the separated pass
        // stops at the break, so on the same range they read differently and
        // overlap. Dropping the separated span then left a whole number in clear
        // (`AB 12 34 56 AB123456\ncDog`, whose `AB 12 34 56 ` only the separated
        // pass reads). A union adds masks and drops none, and it keeps the spans
        // sorted and disjoint as the `overlaps` scan that guarded this needed.
        //
        // NINO-CHAIN: after each number, both passes go on from the offset
        // [`opens_another`] gives — the shared suffix letter itself when the
        // next number starts there, so the scan steps back one byte at most and
        // still always advances. The separated pass records those offsets too: a
        // slashed or dotted head is only its own, and the compact number behind
        // its glued suffix letter is only the other pass's, whose start rule
        // would never look there. The list is sorted, both passes advance, and
        // one cursor walks it: a linear scan still.
        let reads = reads_table(bytes, text, &normalized);
        let mut opens: Vec<usize> = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            let Some(end) = separated_nino_at(bytes, index, text, &normalized, &reads) else {
                index += 1;
                continue;
            };
            if let Some((start, end)) = normalized.to_original(index, end) {
                spans.push(Span::new(EntityKind::UkNino, start, end, 1.0, NAME));
            }
            let next = opens_another(bytes, end, &reads);
            opens.extend(next);
            index = next.map_or(end, |at| at.min(end));
        }
        let (mut index, mut at, mut resume) = (0, 0, 0);
        while index < bytes.len() {
            while at < opens.len() && opens[at] < index {
                at += 1;
            }
            let starts = index == 0
                || index == resume
                || opens.get(at) == Some(&index)
                || !bytes[index - 1].is_ascii_alphanumeric();
            match starts
                .then(|| nino_at(bytes, index, text, &normalized, &reads))
                .flatten()
            {
                Some(end) => {
                    if let Some((start, end)) = normalized.to_original(index, end) {
                        spans.push(Span::new(EntityKind::UkNino, start, end, 1.0, NAME));
                    }
                    let next = opens_another(bytes, end, &reads);
                    // `usize::MAX` is a resume that no offset reaches.
                    resume = next.unwrap_or(usize::MAX);
                    index = next.map_or(end, |at| at.min(end));
                }
                None => index += 1,
            }
        }
        spans.extend(loose_ninos(text));
        union(spans)
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

/// The union of spans that overlap, in start order (NINO-GLUED-NEXT r1). Every
/// span this module makes is a `uk_nino` of the same score and name, so the
/// union of two of them is one of them, ended at the later end.
///
/// Only *overlapping* spans merge, never two that merely touch: two numbers side
/// by side, or a number and the next one on the next line, keep their own spans
/// and their own tokens, exactly as before.
fn union(spans: Vec<Span>) -> Vec<Span> {
    let mut spans = spans;
    spans.sort_unstable_by_key(|span| span.start);
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        let joined = out.last_mut().is_some_and(|last| {
            if span.start < last.end {
                last.end = last.end.max(span.end);
                true
            } else {
                false
            }
        });
        if !joined {
            out.push(span);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<&str> {
        UkNinoRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| &text[span.start..span.end])
            .collect()
    }

    #[test]
    fn a_nino_is_masked_spaced_or_glued() {
        assert_eq!(hits("NI AB123456C"), vec!["AB123456C"]);
        assert_eq!(hits("NI AB 12 34 56 C"), vec!["AB 12 34 56 C"]);
        assert_eq!(hits("CE 12 34 56 A"), vec!["CE 12 34 56 A"]);
        assert_eq!(hits("JG123456B"), vec!["JG123456B"]);
        assert_eq!(hits("AB123456D"), vec!["AB123456D"]);
    }

    #[test]
    fn a_nino_with_mixed_spacing_nbsp_or_fullwidth_is_masked() {
        assert_eq!(hits("NI AB 123456 C"), vec!["AB 123456 C"]);
        assert_eq!(hits("NI AB 12 34 56C"), vec!["AB 12 34 56C"]);
        assert_eq!(hits("NI AB12 34 56 C"), vec!["AB12 34 56 C"]);
        assert_eq!(hits("NI AB-12-34-56-C"), vec!["AB-12-34-56-C"]);
        assert_eq!(
            hits("NI AB\u{a0}12\u{a0}34\u{a0}56\u{a0}C"),
            vec!["AB\u{a0}12\u{a0}34\u{a0}56\u{a0}C"]
        );
        assert_eq!(
            hits("NI \u{ff21}\u{ff22}\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff23}"),
            vec!["\u{ff21}\u{ff22}\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff23}"]
        );
    }

    #[test]
    fn a_lowercase_nino_is_masked() {
        assert_eq!(hits("ni ab123456c"), vec!["ab123456c"]);
        assert_eq!(hits("ab 12 34 56 c"), vec!["ab 12 34 56 c"]);
    }

    #[test]
    fn the_hmrc_excluded_prefixes_are_not_masked() {
        for text in [
            "DA123456A",
            "FA123456A",
            "IA123456A",
            "QA123456A",
            "UA123456A",
            "VA123456A",
            "AD123456A",
            "AF123456A",
            "AI123456A",
            "AO123456A",
            "AQ123456A",
            "AU123456A",
            "AV123456A",
            "BG123456A",
            "GB123456A",
            "NK123456A",
            "KN123456A",
            "TN123456A",
            "NT123456A",
            "ZZ123456A",
        ] {
            assert!(hits(text).is_empty(), "{text} is masked");
        }
    }

    #[test]
    fn qq_the_hmrc_example_is_masked() {
        assert_eq!(hits("QQ123456C"), vec!["QQ123456C"]);
        assert_eq!(hits("QQ 12 34 56 C"), vec!["QQ 12 34 56 C"]);
    }

    #[test]
    fn a_suffix_outside_a_to_d_is_not_masked() {
        assert!(hits("AB123456E").is_empty());
    }

    #[test]
    fn a_nino_next_to_an_underscore_or_a_combining_mark_is_masked() {
        assert_eq!(hits("payslip_AB123456C.pdf"), vec!["AB123456C"]);
        assert_eq!(hits("nino_AB123456C"), vec!["AB123456C"]);
        assert_eq!(hits("AB123456C_old"), vec!["AB123456C"]);
        assert_eq!(hits("AB123456C\u{301}"), vec!["AB123456C"]);
    }

    #[test]
    fn a_rejected_earlier_shape_does_not_hide_a_nino() {
        assert_eq!(hits("sort code 12-34-56 AB123456C"), vec!["AB123456C"]);
        // `XY 12 34 56 A` is itself a separated shape glued to `B`: it overlaps
        // the compact number and the two are one span (NINO-GLUED-NEXT r1).
        assert_eq!(hits("XY 12 34 56 AB123456C"), vec!["XY 12 34 56 AB123456C"]);
        assert_eq!(hits("QQ 12 34 56 AB123456C"), vec!["QQ 12 34 56 AB123456C"]);
        assert_eq!(hits("code 12 34 56 AB 12 34 56 C"), vec!["AB 12 34 56 C"]);
        assert_eq!(hits("DA 12 34 56 AB 12 34 56 C"), vec!["AB 12 34 56 C"]);
        assert_eq!(hits("id: de 12 34 56 ab123456c"), vec!["ab123456c"]);
    }

    #[test]
    fn a_second_nino_glued_to_letters_after_a_line_break_is_read_whole() {
        assert_eq!(
            hits("AB 12 34 56\nBAB123456B"),
            vec!["AB 12 34 56\nB", "AB123456B"]
        );
    }

    #[test]
    fn a_nino_glued_in_a_word_is_not_masked() {
        assert!(hits("XAB123456C").is_empty());
        assert!(hits("AB123456CX").is_empty());
        assert!(hits("9AB123456C").is_empty());
        assert!(hits("AB1234567C").is_empty());
    }

    #[test]
    fn a_separated_nino_glued_to_letters_when_capital_is_masked() {
        assert_eq!(hits("NI PN.48.15.16.C."), vec!["PN.48.15.16.C"]);
        assert_eq!(hits("qq/12/34/56/a"), vec!["qq/12/34/56/a"]);
        assert_eq!(hits("refQQ/12/34/56/Aok"), vec!["QQ/12/34/56/A"]);
        // Pinned over-mask: a capital pair-and-suffix shape before a word.
        assert_eq!(hits("AB 12 34 56 Cars"), vec!["AB 12 34 56 C"]);
    }

    #[test]
    fn a_suffix_glued_to_the_next_line_is_masked_with_the_number() {
        // The glued letter opens the next line, so it is masked with the number
        // and the word is a word again (NINO-GLUED-NEXT).
        assert_eq!(hits("AB 12 34 56\nCblood type A+"), vec!["AB 12 34 56\nC"]);
        assert_eq!(hits("AB123456\nCblood type A+"), vec!["AB123456\nC"]);
        assert_eq!(hits("AB 12 34 56\nC4"), vec!["AB 12 34 56\nC"]);
        // Unless another number starts at that letter: then it is read whole,
        // here with this one, since its own suffix is glued to digits and no
        // pass reads it on its own (FIN-6, NINO-CHAIN r1).
        assert_eq!(
            hits("QQ  12  34  56\nCB 12 34 56 A184127645108946"),
            vec!["QQ  12  34  56\nCB 12 34 56 A"]
        );
    }

    /// Every shape a number may take, so the suffix letter is kept in all of
    /// them and not only where one space or a hyphen separates the pairs
    /// (NINO-GLUED-NEXT r1: a second pattern list that knew only those let every
    /// other shape lose its first letter, and the number behind it stood in
    /// clear). The head is masked too, and where the compact pass keeps the
    /// shared letter the two numbers are one span (NINO-CHAIN).
    #[test]
    fn the_glue_cut_lands_on_every_shape_of_the_next_number() {
        for next in [
            "CB/12/34/56/A",
            "CB.12.34.56.A",
            "CB 12 34 56 A",
            "CB  12  34  56  A",
            "CB   12   34   56   A",
            "CB 12  34 56 A",
            "CB/12/34/56/a",
            "CB-12-34-56-A",
            "CB 12 34 56 a",
            "AB/12/34/56/A",
            "CE/12/34/56/A",
            "CB123456A",
        ] {
            for head in ["AB 12 34 56", "AB-12-34-56", "AB123456", "QQ  12  34  56"] {
                let text = format!("{head}\n{next}");
                let read = UkNinoRecognizer::new().analyze(&text);
                let reach = read.iter().fold(0, |at, span| {
                    if span.start <= at {
                        at.max(span.end)
                    } else {
                        at
                    }
                });
                assert!(
                    reach == text.len(),
                    "{text:?}: not every byte is masked, only {:?}",
                    read.iter()
                        .map(|span| &text[span.start..span.end])
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    /// A first-pass span must never make an older separated one disappear:
    /// `AB 12 34 56 ` and `AB123456\nc` overlap, and dropping the separated span
    /// left a whole number in clear (NINO-GLUED-NEXT r1).
    #[test]
    fn a_first_pass_span_never_suppresses_an_older_separated_one() {
        for text in [
            "AB 12 34 56 AB123456\ncDog walk",
            "AB 12 34 56 AB 12 34 56\ncDog",
            "JG 12 34 56 AB123456\nCblood type A+",
            "QQ  12  34  56  AB123456\nCdog",
        ] {
            let read = UkNinoRecognizer::new().analyze(text);
            // The bytes from 0 to the second number are bytes only the separated
            // pass reads, and the union keeps them: every span starts where the
            // last one ended, and the first one starts at 0.
            assert_eq!(
                read.first().map(|span| span.start),
                Some(0),
                "{text:?}: the first number is not masked at all"
            );
            for pair in read.windows(2) {
                assert_eq!(
                    pair[0].end,
                    pair[1].start,
                    "{text:?}: {:?} to {:?} is in clear",
                    &text[pair[0].start..pair[0].end],
                    &text[pair[1].start..pair[1].end]
                );
            }
        }
    }

    /// ID-LABEL-1: lower case glued, zero-width and doubled separators, and
    /// look-alike capitals, each up to its suffix letter.
    #[test]
    fn loose_spellings_are_read_to_the_suffix() {
        for (text, value) in [
            ("pn 48 15 16 cok", "pn 48 15 16 c"),
            (
                "PN\u{200b}48\u{200b}15\u{200b}16\u{200b}Cok",
                "PN\u{200b}48\u{200b}15\u{200b}16\u{200b}C",
            ),
            ("PN..48..15..16..C", "PN..48..15..16..C"),
            ("РΝ 48 15 16 С).", "РΝ 48 15 16 С"),
            ("NI number: at 12 34 56 cok", "at 12 34 56 c"),
            ("NI number: Rn 18 35 46 bok", "Rn 18 35 46 b"),
            ("NINO - on 12 34 56 dog", "on 12 34 56 d"),
        ] {
            assert_eq!(hits(text), [value], "{text:?}");
        }
    }

    #[test]
    fn a_new_shape_stays_clear_when_it_is_no_nino() {
        for text in [
            "PN/48/15/16/E",
            "PN//48//15//16//C",
            "PN    48    15    16    C",
            "PN/48.15/16/C",
            "PN/48/15/16/C9",
            "9PN/48/15/16/C",
            "refpn 48 15 16 c",
            "table 12 34 56 and",
            // ID-LABEL-1: glued lower case after a short word, a dotted host.
            "at 10 20 30 cats",
            "ab.12.34.56.com",
            "рn 48 15 16 с",
            // Seal A round 1: no explicit NI label right before.
            "at 12 34 56 cok",
            "Rn 18 35 46 bok",
            "ANI number: at 12 34 56 cok",
            "NI number list at 12 34 56 cok",
        ] {
            assert!(hits(text).is_empty(), "{text} is masked");
        }
    }

    #[test]
    fn declared_name() {
        assert_eq!(UkNinoRecognizer::new().name(), "uk_nino");
    }
}
