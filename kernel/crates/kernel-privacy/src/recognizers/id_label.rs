//! National IDs no label rule reaches (ID-LABEL).
//!
//! * A UK driving licence number by its structure, with no label needed:
//!   five surname letters (`9` pads a short name), the birth decade, month
//!   (`+50` for women) and day, the year's last digit, two initials (`9` pads
//!   a missing one), a digit and two check letters (`MORGA753116SM9IJ`), also
//!   grouped 5-6-5 (`MORGA 753116 SM9IJ`). A product, part, order or reference
//!   word right before it (`SKU …`, `Serial: …`) keeps it clear.
//! * The same number under a licence word, in either case and any grouping: a
//!   licence label reads `licence morga657054sm9ij` (ID-LABEL-2),
//!   `Driving licence MORGA-753116-SM9IJ` and `licence MORGA\n753116 SM9IJ`
//!   too. Those three spellings are too ambiguous to read with no label, so
//!   they need the word.
//! * An ID inside a file name: in a name ending in a document or image
//!   extension, with an ID word among its `_`/`-`/`.` parts
//!   (`scan_passport_L898902C3.pdf`, `CNI-X4RTBT9M2.jpg`), each part shaped
//!   like an ID (6–20 capitals and digits, 3+ digits, no date) is masked.
//!
//! Every lookup reads a bounded window around one candidate: linear.

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// The name echoed in [`Span::recognizer`].
const NAME: &str = "id_label";

/// Words right before a licence-shaped code that make it a product's, an
/// order's or a reference's code (folded lower case, ASCII).
const BUSINESS_CUES: &[&str] = &[
    "sku",
    "part",
    "item",
    "product",
    "article",
    "model",
    "serial",
    "order",
    "ref",
    "reference",
    "booking",
    "batch",
    "lot",
    "ticket",
    "tracking",
    "invoice",
    "code",
    "container",
    "shipment",
    "pnr",
    "vin",
    "asset",
    "stock",
];
/// Number words skipped when looking for the cue (`Part no. …`).
const NUMBER_WORDS: &[&str] = &["no", "nr", "num", "number", "id"];
/// How far back the cue is looked for, in bytes.
const CUE_WINDOW: usize = 32;
/// Words that make a licence-shaped code an identity's (ID-LABEL-2): folded,
/// ASCII, so `driver_license_number`, `Driving licence` and `permis` all read
/// one of them. A licence cue is never a business cue's word, so a code both
/// names (`SKU licence MORGA…`) still reads as the label's.
const LICENCE_CUES: &[&str] = &[
    "licence", "licences", "license", "licenses", "permit", "permis",
];

/// File extensions of documents and images an ID scan is kept in.
const EXTENSIONS: &[&str] = &[
    "pdf", "jpg", "jpeg", "png", "heic", "heif", "tif", "tiff", "gif", "bmp", "webp", "doc",
    "docx", "odt",
];
/// Parts of a file name that make it an ID document's (folded lower case).
const ID_WORDS: &[&str] = &[
    "passport",
    "passeport",
    "pasaporte",
    "reisepass",
    "cni",
    "permis",
    "licence",
    "license",
    "ausweis",
    "personalausweis",
    "idcard",
    "identitycard",
    "identite",
    "identity",
    "ssn",
    "nino",
];
/// Longest file name read back from its extension, in bytes.
const MAX_NAME: usize = 128;

/// The recogniser for UK driving licences and IDs inside file names.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdLabelRecognizer;

impl IdLabelRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for IdLabelRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::NationalId]
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let mut spans: Vec<Span> = uk_licences(text)
            .chain(cued_licences(text))
            .map(|(start, end)| Span::new(EntityKind::NationalId, start, end, 1.0, NAME))
            .collect();
        spans.extend(
            file_name_ids(text)
                .map(|(start, end)| Span::new(EntityKind::NationalId, start, end, 1.0, NAME)),
        );
        spans
    }
}

/// Every UK driving licence number in `text`, compact or grouped 5-6-5.
fn uk_licences(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = text.as_bytes();
    (0..bytes.len()).filter_map(move |start| {
        if !bytes[start].is_ascii_uppercase()
            || text[..start]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric)
        {
            return None;
        }
        let window = &bytes[start..bytes.len().min(start + 18)];
        let mut code = [0u8; 16];
        let len = if window.len() >= 18 && window[5] == b' ' && window[12] == b' ' {
            code[..5].copy_from_slice(&window[..5]);
            code[5..11].copy_from_slice(&window[6..12]);
            code[11..].copy_from_slice(&window[13..18]);
            18
        } else if window.len() >= 16 {
            code.copy_from_slice(&window[..16]);
            16
        } else {
            return None;
        };
        // The code is ASCII once its structure holds, so `end` is a char boundary.
        let end = start + len;
        (uk_licence(&code, true)
            && !text[end..].starts_with(char::is_alphanumeric)
            && !business_cue(text, start))
        .then_some((start, end))
    })
}

/// Every UK driving licence number a licence word introduces (ID-LABEL-2): the
/// structure of [`uk_licences`] in either case, grouped over dashes, or split
/// over one line break. Those spellings are read only under the word, so a code
/// no label names keeps main's reading exactly.
fn cued_licences(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = text.as_bytes();
    (0..bytes.len()).filter_map(move |start| {
        if !bytes[start].is_ascii_alphabetic()
            || text[..start]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric)
        {
            return None;
        }
        let (end, _) = licence_shape(text, start)?;
        licence_cue(text, start).then_some((start, end))
    })
}

/// The end of the DVLA licence number written at `start`, and whether it is in
/// capitals: sixteen ASCII alphanumerics in groups joined by one blank, one
/// dash or one line break (`MORGA 753116 SM9IJ`, `MORGA-753116-SM9IJ`,
/// `MORGA\n753116 SM9IJ`), lower case included. One line break at most: a code
/// over two lines is one licence, and three lines are two values. `None` for
/// any other shape.
fn licence_shape(text: &str, start: usize) -> Option<(usize, bool)> {
    let bytes = text.as_bytes();
    let alnum = |at: usize| bytes.get(at).is_some_and(u8::is_ascii_alphanumeric);
    let (mut code, mut at, mut len, mut brk) = ([0u8; 16], start, 0, 0);
    while len < 16 {
        let run = bytes
            .get(at..)?
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric())
            .count();
        if run == 0 || len + run > 16 {
            return None;
        }
        code[len..len + run].copy_from_slice(&bytes[at..at + run]);
        (at, len) = (at + run, len + run);
        if len == 16 {
            break;
        }
        let next = if bytes[at..].starts_with(b"\r\n") && alnum(at + 2) {
            brk += 1;
            2
        } else if matches!(bytes.get(at), Some(b'\n')) && alnum(at + 1) {
            brk += 1;
            1
        } else if matches!(bytes.get(at), Some(b'-' | b' ')) && alnum(at + 1) {
            1
        } else {
            return None;
        };
        if brk > 1 {
            return None;
        }
        at += next;
    }
    let upper = code[0].is_ascii_uppercase();
    (!alnum(at) && uk_licence(&code, upper)).then_some((at, upper))
}

/// Whether a licence word stands within [`CUE_WINDOW`] bytes of `start`, past
/// blanks, punctuation and number words: `his licence number is …`,
/// `driver_license_number: …`.
fn licence_cue(text: &str, start: usize) -> bool {
    let from = text.floor_char_boundary(start.saturating_sub(CUE_WINDOW));
    text[from..start]
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| LICENCE_CUES.contains(&word))
}

/// Whether `code` has the DVLA licence structure, in capitals or lower case.
fn uk_licence(code: &[u8; 16], upper: bool) -> bool {
    let digit = |b: u8| b.is_ascii_digit();
    let letter = |b: u8| {
        if upper {
            b.is_ascii_uppercase()
        } else {
            b.is_ascii_lowercase()
        }
    };
    let surname = &code[..5];
    let padding = surname.iter().position(|&b| b == b'9').unwrap_or(5);
    let two = |at: usize| (code[at] - b'0') * 10 + code[at + 1] - b'0';
    if !(letter(code[0])
        && surname[..padding].iter().all(|&b| letter(b))
        && surname[padding..].iter().all(|&b| b == b'9')
        && digit(code[5])
        && code[6..10].iter().all(|&b| digit(b))
        && digit(code[10])
        && letter(code[11])
        && (letter(code[12]) || code[12] == b'9')
        && digit(code[13])
        && letter(code[14])
        && letter(code[15]))
    {
        return false;
    }
    let month = two(6) % 50;
    (1..=12).contains(&month) && (1..=31).contains(&two(8))
}

/// Whether a product, order or reference word stands right before `start`,
/// past blanks, punctuation and number words (`Part no. …`, `SKU: …`).
fn business_cue(text: &str, start: usize) -> bool {
    let from = text.floor_char_boundary(start.saturating_sub(CUE_WINDOW));
    let window = text[from..start].to_ascii_lowercase();
    window
        .split(|c: char| !c.is_ascii_alphanumeric())
        .rev()
        .find(|word| !word.is_empty() && !NUMBER_WORDS.contains(word))
        .is_some_and(|word| BUSINESS_CUES.contains(&word))
}

/// Every ID-shaped part of a file name that holds an ID word.
fn file_name_ids(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    text.match_indices('.').flat_map(move |(dot, _)| {
        let after = &text[dot + 1..];
        let ext = after
            .find(|c: char| !c.is_ascii_alphanumeric())
            .map_or(after, |len| &after[..len]);
        let known = EXTENSIONS.iter().any(|e| e.eq_ignore_ascii_case(ext))
            && !after[ext.len()..].starts_with(char::is_alphanumeric);
        let start = known.then(|| name_start(text, dot)).flatten();
        start
            .into_iter()
            .flat_map(move |start| id_parts(text, start, dot))
    })
}

/// The start of the file name ending at `dot`: back over letters, digits, `_`,
/// `-` and `.`, at most [`MAX_NAME`] bytes. `None` when the name is longer.
fn name_start(text: &str, dot: usize) -> Option<usize> {
    let from = text.floor_char_boundary(dot.saturating_sub(MAX_NAME));
    let name = |c: char| c.is_alphanumeric() || "_-.".contains(c);
    let start = text[from..dot]
        .char_indices()
        .rev()
        .find(|&(_, c)| !name(c))
        .map(|(at, c)| from + at + c.len_utf8());
    match start {
        Some(start) => Some(start),
        None if from == 0 => Some(0),
        None => None,
    }
}

/// The ID-shaped parts of the name `text[start..dot]`, when one part is an ID
/// word.
fn id_parts(text: &str, start: usize, dot: usize) -> Vec<(usize, usize)> {
    let base = &text[start..dot];
    let parts = || {
        base.split(['_', '-', '.']).scan(start, |at, part| {
            let here = *at;
            *at += part.len() + 1;
            Some((here, part))
        })
    };
    if !parts().any(|(_, part)| ID_WORDS.iter().any(|w| w.eq_ignore_ascii_case(part))) {
        return Vec::new();
    }
    parts()
        .filter(|(_, part)| id_shaped(part))
        .map(|(at, part)| (at, at + part.len()))
        .collect()
}

/// 6–20 ASCII letters and digits, 3+ of them digits, no run of three lower-case
/// letters (`scan001`, `page12`), and no `YYYYMMDD` date.
fn id_shaped(part: &str) -> bool {
    let bytes = part.as_bytes();
    let digits = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    let lower_run = bytes
        .windows(3)
        .any(|w| w.iter().all(u8::is_ascii_lowercase));
    let date = digits == 8 && bytes.len() == 8 && {
        let n = |r: std::ops::Range<usize>| part[r].parse::<u32>().unwrap_or(0);
        (1900..2100).contains(&n(0..4))
            && (1..=12).contains(&n(4..6))
            && (1..=31).contains(&n(6..8))
    };
    (6..=20).contains(&bytes.len())
        && bytes.iter().all(u8::is_ascii_alphanumeric)
        && digits >= 3
        && !lower_run
        && !date
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(text: &str) -> Vec<&str> {
        IdLabelRecognizer::new()
            .analyze(text)
            .iter()
            .map(|span| &text[span.start..span.end])
            .collect()
    }

    #[test]
    fn licences_and_file_name_ids_are_found() {
        for (text, value) in [
            ("licence MORGA753116SM9IJ.", "MORGA753116SM9IJ"),
            ("MA999701160AB9XY", "MA999701160AB9XY"),
            ("SMITH802115J99RT", "SMITH802115J99RT"),
            ("is MORGA 753116 SM9IJ", "MORGA 753116 SM9IJ"),
            ("scan_passport_L898902C3.pdf", "L898902C3"),
            ("(passeport-20AB71234-verso.PNG)", "20AB71234"),
            ("DE_Personalausweis_LZ6311T47_front.jpg", "LZ6311T47"),
        ] {
            assert!(
                masked(text).contains(&value),
                "{text:?}: {:?}",
                masked(text)
            );
        }
    }

    /// ID-LABEL-2: a licence word reads the same structure in either case, over
    /// dashes, and across one line break.
    #[test]
    fn a_licence_word_reads_every_spelling_of_the_number() {
        for (text, value) in [
            (
                "his licence number is morga753116sm9ij.",
                "morga753116sm9ij",
            ),
            ("license: morga753116sm9ij", "morga753116sm9ij"),
            ("licence morga 753116 sm9ij", "morga 753116 sm9ij"),
            ("Driving licence MORGA-753116-SM9IJ", "MORGA-753116-SM9IJ"),
            ("licence number MORGA-753116-SM9IJ", "MORGA-753116-SM9IJ"),
            ("licence MORGA\n753116 SM9IJ", "MORGA\n753116 SM9IJ"),
            (
                "Driving licence\r\nMORGA-753116-SM9IJ",
                "MORGA-753116-SM9IJ",
            ),
            ("permis morga753116sm9ij", "morga753116sm9ij"),
        ] {
            assert!(
                masked(text).contains(&value),
                "{text:?}: {:?}",
                masked(text)
            );
        }
    }

    #[test]
    fn lookalikes_stay_clear() {
        for text in [
            "SKU MORGA753116SM9IJ",
            "Part no. MORGA753116SM9IJ",
            "MORGA753116SM9IJX",
            "MORGA713116SM9IJ",
            "MORGA753116SM9I1",
            "M9RGA753116SM9IJ",
            "IMG_20240301_101500.jpg",
            "passport_20240301.pdf",
            "passport_scan001.pdf",
            "build_L898902C3.zip",
            "order_A7K29Q4M1.pdf",
            "scan_passport_⟦NATIONAL_ID_0123456789AB⟧.pdf",
            // ID-LABEL-2: no licence word, so the new spellings stay clear.
            "MORGA-753116-SM9IJ",
            "morga753116sm9ij",
            "MORGA\n753116 SM9IJ",
            // A licence word, but no licence number.
            "licence fee of 159 pounds",
            "licence: 2024-10-01",
            "version 1.2.3",
            "the licence and the permit are separate",
            "licence MORGA-753116-SM9IJX",
        ] {
            assert!(masked(text).is_empty(), "{text:?}: {:?}", masked(text));
        }
    }

    #[test]
    fn utf8_edges_never_panic() {
        for text in [
            "é.pdf",
            ".pdf",
            "passport_é1234567.pdf",
            "ÉMORGA753116SM9IJ",
            "a.",
            "é morga753116sm9ij",
            "licence é",
            "licence MORGA-753116-",
            "licence MORGA\n\n753116 SM9IJ",
        ] {
            let _ = masked(text);
        }
        let long = format!("{}passport_L898902C3.pdf", "é".repeat(100));
        let _ = masked(&long);
    }
}
