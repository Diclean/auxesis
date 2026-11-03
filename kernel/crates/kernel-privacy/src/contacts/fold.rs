//! Folding for the contact matcher.
//!
//! Names are compared case-, diacritic- and separator-insensitively. [`fold`]
//! turns text into a lowercase, accent-free string in which every run of
//! non-letters (spaces, hyphens, apostrophes, punctuation) is one space. For
//! every byte of the folded string it records the bytes of the original text
//! it came from, so a match in the folded string maps back to an exact byte
//! span of the original text.

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

/// Folded text with a map from each folded byte back to its source bytes.
pub(crate) struct Folded {
    text: String,
    source_start: Vec<usize>,
    source_end: Vec<usize>,
}

impl Folded {
    /// The folded text.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// The source byte range covered by the folded bytes `start..end`.
    ///
    /// `start < end` must hold, and both bounds must lie on folded character
    /// boundaries (as the matches of the automaton do).
    pub(crate) fn source(&self, start: usize, end: usize) -> (usize, usize) {
        (self.source_start[start], self.source_end[end - 1])
    }

    fn push(&mut self, c: char, start: usize, end: usize) {
        self.text.push(c);
        for _ in 0..c.len_utf8() {
            self.source_start.push(start);
            self.source_end.push(end);
        }
    }

    /// Emit one space for a run of separators, never a leading one.
    fn separator(&mut self, start: usize, end: usize) {
        if !self.text.is_empty() && !self.text.ends_with(' ') {
            self.push(' ', start, end);
        }
    }

    /// Extend the source span of the last folded character to `end`. Folding
    /// skips a combining mark, but the mark belongs to the letter it follows, so
    /// a match that ends on that letter covers the mark too.
    fn extend_last(&mut self, end: usize) {
        let Some(&last) = self.source_end.last() else {
            return;
        };
        for at in self
            .source_end
            .iter_mut()
            .rev()
            .take_while(|at| **at == last)
        {
            *at = end;
        }
    }
}

/// Fold `text` for matching. See the module documentation.
pub(crate) fn fold(text: &str) -> Folded {
    fold_with(text, false, false, false, false)
}

/// Like [`fold`], with the common Cyrillic and Greek look-alikes of Latin letters
/// folded to Latin inside a Latin word, so `C\u{430}mille` matches `Camille`.
/// Every other word keeps its letters: a pure word is not read as Latin, so
/// `папа` is not `Nana`. Cyrillic and Greek are out of Private mode's language
/// scope (owner 2026-10-10), so no Cyrillic or Greek word folds to another letter.
pub(crate) fn fold_homoglyphs(text: &str) -> Folded {
    fold_with(text, false, true, true, true)
}

/// Like [`fold`], but every Default_Ignorable character is read as a separator
/// instead of being deleted, so a hidden character splits a word.
pub(crate) fn fold_separators(text: &str) -> Folded {
    fold_with(text, true, false, false, false)
}

/// Like [`fold_homoglyphs`], but with the Default_Ignorable characters read as
/// separators instead of being deleted.
pub(crate) fn fold_separators_homoglyphs(text: &str) -> Folded {
    fold_with(text, true, true, true, true)
}

/// [`fold_homoglyphs`] without the diacritic transliterations: `Müller` folds to
/// `muller`, where [`fold_homoglyphs`] gives `mueller`.
pub(crate) fn fold_homoglyphs_plain(text: &str) -> Folded {
    fold_with(text, false, true, false, true)
}

/// [`fold_separators_homoglyphs`] without the diacritic transliterations.
pub(crate) fn fold_separators_homoglyphs_plain(text: &str) -> Folded {
    fold_with(text, true, true, false, true)
}

fn fold_with(
    text: &str,
    zero_width_is_separator: bool,
    homoglyphs: bool,
    transliterate: bool,
    arabic: bool,
) -> Folded {
    let mut folded = Folded {
        text: String::with_capacity(text.len()),
        source_start: Vec::with_capacity(text.len()),
        source_end: Vec::with_capacity(text.len()),
    };
    let scripts = if homoglyphs {
        word_scripts(text)
    } else {
        Vec::new()
    };
    for (start, original) in text.char_indices() {
        let end = start + original.len_utf8();
        let c = ascii_apostrophe(original);
        if is_combining(c) {
            folded.extend_last(end);
            continue;
        }
        if is_default_ignorable(c) {
            if zero_width_is_separator {
                folded.separator(start, end);
            }
            continue;
        }
        if c.is_ascii() {
            if c.is_ascii_alphanumeric() {
                let letter = c.to_ascii_lowercase();
                // A Latin letter in a Cyrillic or Greek word is a look-alike.
                let canonical = if homoglyphs {
                    homoglyph_in(letter, scripts[start])
                } else {
                    None
                };
                folded.push(canonical.unwrap_or(letter), start, end);
            } else {
                folded.separator(start, end);
            }
        } else if c.is_alphanumeric() || is_indic_sign(c) {
            fold_letter(c, transliterate, |letter| {
                // The homoglyph and Arabic maps run after NFKD, mark
                // stripping, the case folding and the expansions, so both
                // cases of a look-alike reach the same canonical letter.
                if homoglyphs {
                    if let Some(canonical) = homoglyph_in(letter, scripts[start]) {
                        folded.push(canonical, start, end);
                        return;
                    }
                }
                if arabic {
                    if let Some(canonical) = arabic_fold(letter, text, end) {
                        folded.push(canonical, start, end);
                        return;
                    }
                }
                if letter.is_alphanumeric() || is_indic_sign(letter) {
                    folded.push(letter, start, end);
                } else {
                    folded.separator(start, end);
                }
            });
        } else {
            folded.separator(start, end);
        }
    }
    while folded.text.ends_with(' ') {
        folded.text.pop();
        folded.source_start.pop();
        folded.source_end.pop();
    }
    folded
}

/// The apostrophe a modifier letter or typographic quote stands for: the
/// ASCII `'`, which folding reads as a separator, so `Camilleʼs`, `Dar’ya` and
/// `G‘ulom` fold like `Camille's`, `Dar'ya` and `G'ulom`.
fn ascii_apostrophe(c: char) -> char {
    match c {
        '\u{02BB}' | '\u{02BC}' | '\u{02BD}' | '\u{02C8}' | '\u{2018}' | '\u{2019}'
        | '\u{0060}' | '\u{00B4}' => '\'',
        other => other,
    }
}

/// Lowercase, accent-free text of `text`, without the source map.
pub(crate) fn folded_text(text: &str) -> String {
    fold(text).text
}

/// `text` composed (NFKC) and lower-cased, for matching e-mail addresses. Every
/// character is kept, so `@`, `.` and `%40` stay as written. A base character
/// and the combining marks after it form one cluster: the cluster is composed
/// on its own, and every byte it yields maps back to the cluster's source bytes.
pub(crate) fn lower_nfkc(text: &str) -> Folded {
    let mut folded = Folded {
        text: String::with_capacity(text.len()),
        source_start: Vec::with_capacity(text.len()),
        source_end: Vec::with_capacity(text.len()),
    };
    let mut characters = text.char_indices().peekable();
    while let Some((start, first)) = characters.next() {
        let mut end = start + first.len_utf8();
        while let Some(&(at, mark)) = characters.peek() {
            if !is_combining_mark(mark) {
                break;
            }
            end = at + mark.len_utf8();
            characters.next();
        }
        for composed in text[start..end].nfkc() {
            for lower in composed.to_lowercase() {
                folded.push(lower, start, end);
            }
        }
    }
    folded
}

/// The spellings an address takes in running text, lower-case, as the text
/// reads after [`lower_nfkc`]: `[at]`, `(at)`, ` at `, and the `dot` forms.
const AT_SPELLINGS: &[(&str, char)] = &[
    (" [at] ", '@'),
    (" (at) ", '@'),
    (" at ", '@'),
    ("[at]", '@'),
    ("(at)", '@'),
];
const DOT_SPELLINGS: &[(&str, char)] = &[
    (" [dot] ", '.'),
    (" (dot) ", '.'),
    (" dot ", '.'),
    ("[dot]", '.'),
    ("(dot)", '.'),
];

/// The text of `lower` with the obfuscated and percent-encoded spellings of an
/// address read as the characters they stand for: `%40` and `%2E` (and any
/// percent-encoded printable ASCII), `[at]` and `(at)` and ` at `, `[dot]` and
/// `(dot)` and ` dot `. Every character keeps its source bytes in `lower`'s
/// original text, so a match maps back to an exact span of the original.
pub(crate) fn plain_address(lower: &Folded) -> Folded {
    let text = lower.text.as_str();
    let mut out = Folded {
        text: String::with_capacity(text.len()),
        source_start: Vec::with_capacity(text.len()),
        source_end: Vec::with_capacity(text.len()),
    };
    let mut at = 0;
    while at < text.len() {
        let (len, emitted) = spelling_at(&text[at..]).unwrap_or_else(|| {
            let letter = text[at..].chars().next().unwrap_or_default();
            (letter.len_utf8(), letter)
        });
        let (start, end) = lower.source(at, at + len);
        out.push(emitted, start, end);
        at += len;
    }
    out
}

/// The length in bytes and the letter of the spelling at the start of `rest`,
/// when one starts there.
fn spelling_at(rest: &str) -> Option<(usize, char)> {
    let bytes = rest.as_bytes();
    if bytes.first() == Some(&b'%') && bytes.len() >= 3 {
        let value = (hex_digit(bytes[1])? << 4) | hex_digit(bytes[2])?;
        if (0x21..=0x7e).contains(&value) {
            return Some((3, char::from(value).to_ascii_lowercase()));
        }
    }
    AT_SPELLINGS
        .iter()
        .chain(DOT_SPELLINGS)
        .find(|(spelling, _)| rest.starts_with(spelling))
        .map(|(spelling, letter)| (spelling.len(), *letter))
}

/// The value of one ASCII hex digit.
fn hex_digit(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

/// Decompose a letter (compatibility form, so full-width letters and ligatures
/// fold to their plain letters), drop its combining marks, lowercase it and
/// expand the few letters that have no decomposition (`ß`, `ø`, `ł`, …).
fn fold_letter(c: char, transliterate: bool, mut emit: impl FnMut(char)) {
    // A precomposed diacritic (`ü`, `Å`) expands before NFKD would strip its
    // mark, so the transliteration is checked on the folded character first.
    if transliterate {
        for lower in c.to_lowercase() {
            if let Some(letters) = transliteration(lower) {
                for letter in letters.chars() {
                    emit(letter);
                }
                return;
            }
        }
    }
    for base in std::iter::once(c).nfkd() {
        if is_combining(base) {
            continue;
        }
        for lower in base.to_lowercase() {
            match expansion(lower) {
                Some(letters) => {
                    for letter in letters.chars() {
                        emit(letter);
                    }
                }
                None => emit(lower),
            }
        }
    }
}

/// The diacritic transliterations the dictionary adds on top of [`expansion`]:
/// `Müller` and `Mueller` fold to the same string, in both directions.
fn transliteration(c: char) -> Option<&'static str> {
    Some(match c {
        'ä' => "ae",
        'ö' => "oe",
        'ü' => "ue",
        'ø' => "oe",
        'å' => "aa",
        'æ' => "ae",
        'ß' => "ss",
        'œ' => "oe",
        other => return expansion(other),
    })
}

/// The Arabic letters that are written more than one way, folded to one form.
/// The teh marbuta `ة` folds to heh `ه` only at the end of a word, where the
/// two are interchangeable; elsewhere it is a different letter and stays.
fn arabic_fold(c: char, text: &str, end: usize) -> Option<char> {
    Some(match c {
        '\u{0622}' | '\u{0623}' | '\u{0625}' | '\u{0627}' => '\u{0627}',
        '\u{0649}' | '\u{064A}' | '\u{06CC}' => '\u{064A}',
        '\u{0643}' | '\u{06A9}' => '\u{0643}',
        '\u{0629}' if word_final(text, end) => '\u{0647}',
        _ => return None,
    })
}

/// Whether the letter ending at `end` closes a word: the next character that is
/// neither a mark nor an ignorable is not a letter or digit.
fn word_final(text: &str, end: usize) -> bool {
    text[end..]
        .chars()
        .find(|c| !is_combining(*c) && !is_default_ignorable(*c))
        .is_none_or(|c| !c.is_alphanumeric())
}

/// Whether `c` is a combining sign of an Indic script: a vowel sign, a nukta or
/// a virama. These are not diacritics and not separators, so they stay inside
/// a word (`ரவிக்கு` is one word, and `अनुको` has the stem `अनु`).
pub(crate) fn is_indic_sign(c: char) -> bool {
    matches!(
        c,
        '\u{0900}'..='\u{0903}'
            | '\u{093A}'..='\u{094F}'
            | '\u{0951}'..='\u{0957}'
            | '\u{0962}'..='\u{0963}'
            | '\u{0981}'..='\u{0983}'
            | '\u{09BC}'
            | '\u{09BE}'..='\u{09CD}'
            | '\u{09D7}'
            | '\u{09E2}'..='\u{09E3}'
            | '\u{0BBE}'..='\u{0BCD}'
            | '\u{0BD7}'
    )
}

/// Whether `c` belongs to a script written without spaces between words.
pub(crate) fn is_no_space_script(c: char) -> bool {
    matches!(c,
        '\u{2E80}'..='\u{2EFF}'
        | '\u{3000}'..='\u{303F}'
        | '\u{3040}'..='\u{309F}'
        | '\u{30A0}'..='\u{30FF}'
        | '\u{3100}'..='\u{312F}'
        | '\u{3130}'..='\u{318F}'
        | '\u{31F0}'..='\u{31FF}'
        | '\u{3400}'..='\u{4DBF}'
        | '\u{4E00}'..='\u{9FFF}'
        | '\u{A960}'..='\u{A97F}'
        | '\u{AC00}'..='\u{D7AF}'
        | '\u{D7B0}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FAFF}'
        | '\u{FE30}'..='\u{FE4F}'
        | '\u{FF00}'..='\u{FFEF}'
        | '\u{0E00}'..='\u{0E7F}'
        | '\u{0E80}'..='\u{0EFF}'
        | '\u{1000}'..='\u{109F}'
        | '\u{1780}'..='\u{17FF}'
        | '\u{19E0}'..='\u{19FF}'
        | '\u{1100}'..='\u{11FF}'
        | '\u{A9E0}'..='\u{A9FF}'
        | '\u{AA60}'..='\u{AA7F}'
        | '\u{20000}'..='\u{2FA1F}'
    )
}

/// Letters folded to one or more other letters. Arabic alef forms collapse to
/// bare alef, and alef maqsura to yeh, so the usual spelling variants match.
fn expansion(c: char) -> Option<&'static str> {
    Some(match c {
        'ß' => "ss",
        'æ' => "ae",
        'œ' => "oe",
        'þ' => "th",
        'ø' => "o",
        'ł' => "l",
        'đ' | 'ð' => "d",
        'ı' => "i",
        'أ' | 'إ' | 'آ' | 'ٱ' => "ا",
        'ى' => "ي",
        // Final sigma is lower-cased to `ς` only at the end of a word; folding
        // it to `σ` makes "ΣΆΒΒΑΣ" and "σαββας" the same name.
        'ς' => "σ",
        _ => return None,
    })
}

/// The script a word is written in: the one most of its letters use, Latin on
/// a tie. A word with no letter of these three scripts is `Other`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WordScript {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

/// For each byte offset of `text` that starts a letter, the script of the word
/// that holds it. A word is a run of letters and digits; marks and
/// Default_Ignorable characters do not end it, so a hidden character cannot
/// split a word from the look-alikes inside it.
fn word_scripts(text: &str) -> Vec<WordScript> {
    let mut scripts = vec![WordScript::Other; text.len()];
    let mut word: Vec<usize> = Vec::new();
    // Latin, Cyrillic and Greek letters of the word so far.
    let mut counts = [0usize; 3];
    for (start, c) in text.char_indices() {
        if is_combining(c) || is_default_ignorable(c) {
            continue;
        }
        if c.is_alphanumeric() || is_indic_sign(c) {
            word.push(start);
            if is_latin_letter(c) {
                counts[0] += 1;
            } else if is_cyrillic(c) {
                counts[1] += 1;
            } else if is_greek(c) {
                counts[2] += 1;
            }
        } else {
            settle_word(&mut scripts, &mut word, &mut counts);
        }
    }
    settle_word(&mut scripts, &mut word, &mut counts);
    scripts
}

/// Record the script of the finished word for each of its letters, and reset.
fn settle_word(scripts: &mut [WordScript], word: &mut Vec<usize>, counts: &mut [usize; 3]) {
    let [latin, cyrillic, greek] = *counts;
    let script = if latin > 0 && latin >= cyrillic && latin >= greek {
        WordScript::Latin
    } else if cyrillic > 0 && cyrillic >= greek {
        WordScript::Cyrillic
    } else if greek > 0 {
        WordScript::Greek
    } else {
        WordScript::Other
    };
    for &at in word.iter() {
        scripts[at] = script;
    }
    word.clear();
    *counts = [0; 3];
}

/// Whether `c` is a Cyrillic letter.
pub(crate) fn is_cyrillic(c: char) -> bool {
    matches!(c, '\u{0400}'..='\u{052F}')
}

/// Whether `c` is a Greek letter.
pub(crate) fn is_greek(c: char) -> bool {
    matches!(c, '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}')
}

/// The canonical letter a homoglyph folds to in a word of `script`. Only a Latin
/// word takes the Cyrillic and Greek look-alikes; any other word keeps its
/// letters, so Cyrillic `і` and `и` stay distinct.
fn homoglyph_in(letter: char, script: WordScript) -> Option<char> {
    match script {
        WordScript::Latin => homoglyph(letter),
        WordScript::Cyrillic | WordScript::Greek | WordScript::Other => None,
    }
}

/// Whether `c` is a Latin letter, compatibility forms included (`Ｃ`, `ℂ`), so
/// that a full-width or letter-like Latin character counts as Latin.
fn is_latin_letter(c: char) -> bool {
    std::iter::once(c).nfkd().any(|base| {
        base != '\u{00D7}'
            && base != '\u{00F7}'
            && (base.is_ascii_alphabetic()
                || matches!(base, '\u{00C0}'..='\u{024F}' | '\u{1E00}'..='\u{1EFF}'))
    })
}

/// Whether `c` is a Latin letter that a diacritic strip or a transliteration
/// spells differently (`ä`, `ø`, `ß`, `ł`). A plain Latin letter is not one.
pub(crate) fn is_latin_diacritic(c: char) -> bool {
    !c.is_ascii()
        && is_latin_letter(c)
        && (std::iter::once(c)
            .nfd()
            .next()
            .is_some_and(|base| base.is_ascii_alphabetic())
            || c.to_lowercase()
                .any(|lower| transliteration(lower).is_some()))
}

/// The common Cyrillic and Greek characters that read as a Latin letter.
pub(crate) fn homoglyph(c: char) -> Option<char> {
    Some(match c {
        // Cyrillic
        '\u{0430}' => 'a',
        '\u{0432}' => 'b',
        '\u{0435}' => 'e',
        '\u{0433}' => 'r',
        '\u{043A}' => 'k',
        '\u{043C}' => 'm',
        '\u{043D}' => 'h',
        '\u{043E}' => 'o',
        '\u{043F}' => 'n',
        '\u{0440}' => 'p',
        '\u{0441}' => 'c',
        '\u{0442}' => 't',
        '\u{0443}' => 'y',
        '\u{0445}' => 'x',
        '\u{0456}' => 'i',
        '\u{0458}' => 'j',
        '\u{0455}' => 's',
        '\u{0501}' => 'd',
        '\u{04CF}' => 'l',
        // Greek
        '\u{0391}' => 'a',
        '\u{0392}' => 'b',
        '\u{0395}' => 'e',
        '\u{0396}' => 'z',
        '\u{0397}' => 'h',
        '\u{0399}' => 'i',
        '\u{039A}' => 'k',
        '\u{039C}' => 'm',
        '\u{039D}' => 'n',
        '\u{039F}' => 'o',
        '\u{03A1}' => 'p',
        '\u{03A4}' => 't',
        '\u{03A7}' => 'x',
        '\u{03A5}' => 'y',
        '\u{03B1}' => 'a',
        '\u{03B2}' => 'b',
        '\u{03B5}' => 'e',
        '\u{03B6}' => 'z',
        '\u{03B7}' => 'n',
        '\u{03B9}' => 'i',
        '\u{03BA}' => 'k',
        '\u{03BC}' => 'm',
        '\u{03BD}' => 'v',
        '\u{03BF}' => 'o',
        '\u{03C1}' => 'p',
        '\u{03C4}' => 't',
        '\u{03C5}' => 'u',
        '\u{03C7}' => 'x',
        _ => return None,
    })
}

/// Every Unicode `Default_Ignorable_Code_Point`, plus the Hangul fillers: the
/// characters that are invisible for matching. This is the one definition the
/// folder and the name-region scanner share.
pub(crate) fn is_default_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{0640}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Combining marks, including the Arabic harakat and Quranic signs. The vowel
/// and tone marks of the Indic and Thai-Lao scripts are not diacritics: they
/// stay, so `राहुल` and `रहल` are different names and a stem keeps its length.
fn is_combining(c: char) -> bool {
    if matches!(c, '\u{0900}'..='\u{0DFF}' | '\u{0E00}'..='\u{0EFF}') {
        return false;
    }
    is_combining_mark(c)
        || matches!(
            c,
            '\u{0300}'..='\u{036F}'
                | '\u{0610}'..='\u{061A}'
                | '\u{064B}'..='\u{065F}'
                | '\u{0670}'
                | '\u{06D6}'..='\u{06DC}'
                | '\u{06DF}'..='\u{06E4}'
                | '\u{06E7}'..='\u{06E8}'
                | '\u{06EA}'..='\u{06ED}'
                | '\u{1AB0}'..='\u{1AFF}'
                | '\u{1DC0}'..='\u{1DFF}'
                | '\u{20D0}'..='\u{20FF}'
                | '\u{FE20}'..='\u{FE2F}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_case_accents_and_separators() {
        assert_eq!(folded_text("Bálint  Kovács"), "balint kovacs");
        assert_eq!(folded_text("Jean-Marc D'Angelo"), "jean marc d angelo");
        assert_eq!(folded_text("Straße Øre"), "strasse ore");
        assert_eq!(folded_text("ЁЖИК Иван"), "ежик иван");
        assert_eq!(folded_text("محمّد عَلِي"), "محمد علي");
    }

    #[test]
    fn source_map_points_back_into_the_original() {
        let text = "Bonjour, Éloïse Martin!";
        let folded = fold(text);
        let found = folded.text().find("eloise martin").expect("folded name");
        let (start, end) = folded.source(found, found + "eloise martin".len());
        assert_eq!(&text[start..end], "Éloïse Martin");
    }

    #[test]
    fn leading_and_trailing_separators_vanish() {
        assert_eq!(fold("  -- Marie --  ").text(), "marie");
    }

    #[test]
    fn full_width_letters_ligatures_and_final_sigma_fold_to_plain_letters() {
        assert_eq!(folded_text("ＭＡＲＩＥ　ＤＵＰＯＮＴ"), "marie dupont");
        assert_eq!(folded_text("\u{FB01}scher"), "fischer");
        assert_eq!(folded_text("ΣΆΒΒΑΣ"), folded_text("σαββας"));
    }

    #[test]
    fn a_non_letter_from_a_compatibility_form_is_a_separator() {
        assert_eq!(folded_text("a\u{2044}b"), "a b");
    }

    #[test]
    fn plain_address_reads_obfuscated_and_percent_forms_with_source_offsets() {
        let text = "JULES [at] Example [dot] invalid, jules%40example%2Einvalid, jules(at)example";
        let plain = plain_address(&lower_nfkc(text));
        assert!(
            plain.text().contains("jules@example.invalid"),
            "{}",
            plain.text()
        );
        assert!(plain.text().contains("jules@example.invalid,"));
        assert!(plain.text().ends_with("jules@example"));
        let found = plain.text().find("jules@example.invalid").expect("address");
        let (start, end) = plain.source(found, found + "jules@example.invalid".len());
        assert_eq!(&text[start..end], "JULES [at] Example [dot] invalid");
    }

    #[test]
    fn lower_nfkc_composes_lowercases_and_maps_back() {
        let text = "ÉLODIE E\u{301}x";
        let folded = lower_nfkc(text);
        assert_eq!(folded.text(), "élodie éx");
        let found = folded.text().find("éx").expect("folded");
        let (start, end) = folded.source(found, found + "éx".len());
        assert_eq!(&text[start..end], "E\u{301}x");
    }
}
