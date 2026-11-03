//! Passport-number recogniser.
//!
//! A passport number is masked on its shape, never on its check digit alone:
//! a typo in a real document is still personal data (maintainer policy, P1).
//!
//! * the ICAO 9303 7-3-1 check digit is still computed, but only to *raise* the
//!   score of a ten-character payload+check value;
//! * without a cue the strict `[A-Z]{1,3}[0-9]{6,9}` passport shape is masked
//!   on sight, with at most one hyphen or dot between the letter prefix and the
//!   digits; a single *space* is masked too for **every** 1–3 letter prefix and
//!   7–9 digits, or when the de-spaced value passes the ICAO 7-3-1 check digit.
//!   `ISO` and a short business-reference denylist ([`BUSINESS_PREFIXES`], e.g.
//!   `REF 1234567`) stay clear, and the cued `TAJ 123456788` keeps its `HU_TAJ`
//!   label, because those prefixes are cues for other rules;
//! * a passport cue (`passeport`, `passport`, `paspoort`, `útlevél`,
//!   `паспорт`, `جواز`, `MRZ`, `P<`) is searched for 64 characters *before and
//!   after* a value; near one the broader 8–10 alphanumeric shape with at least
//!   five digits is masked too.
//!
//! Every rule runs over the shared normalised view (P1): Arabic-Indic, Persian
//! and fullwidth digits all become ASCII digits and fullwidth letters become
//! ASCII, while matching is case-insensitive, so `passeport l898902c36` and
//! `جواز السفر QXZ١٢٣٤٥٦٧` are both masked. Spans are reported on the original
//! byte offsets.
//!
//! The recogniser is `verified: false`, so the registry labels its hits
//! `NATIONAL_ID` at a lower score; that is deliberate, the specific ICAO rule
//! is not confirmed against Doc 9303.

use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use crate::checksum::passport_mrz_ok;
use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::recognizers::iban::{uuid_tokens, IbanRecognizer};
use crate::span::{EntityKind, Span};

/// Score of an 8–10 alphanumeric value near a cue with no valid check digit.
pub const BROAD_SCORE: f32 = 0.55;
/// Score of the strict passport shape with no valid check digit.
pub const STRICT_SCORE: f32 = 0.8;

/// Characters inspected before and after a candidate for a passport cue.
const CUE_WINDOW: usize = 64;
/// Cue words that widen the shape (P1). `P<` is the MRZ document-code prefix;
/// matching is case-insensitive, so `p<` covers it.
const CUES: &[&str] = &[
    "passeport",
    "passport",
    "paspoort",
    "útlevél",
    "паспорт",
    "جواز",
    "mrz",
    "p<",
];

/// Letter prefixes that are a cue for another recogniser, so the specific rule
/// decides both the label and the span: a spaced `TAJ 123456788` stays the
/// Hungarian TAJ hit and `ISO 123456` is an international standard.
const NON_PASSPORT_PREFIXES: &[&str] = &["iso", "taj"];

/// Common business-reference prefixes that stay clear in the *cue-less spaced*
/// form, so an order/invoice/article reference (`REF 1234567`) is not masked as
/// a passport. Deliberately short and only consulted for the space-separated
/// shape, after a whole-word prefix; the hyphen/dot forms are unambiguous
/// attachment and still mask. `N°` is listed for completeness even though the
/// `°` means the separated regex never yields it as a prefix.
const BUSINESS_PREFIXES: &[&str] = &["ref", "inv", "fa", "cmd", "po", "no", "n°", "nr", "art"];

/// A machine-readable zone line (ICAO 9303 TD1/TD2/TD3: 30, 36 or 44 chars,
/// OCR may drop a few): a run of at least [`MRZ_LINE_MIN`] letters, digits and
/// `<` that holds a `<<` filler. Such a run is one maximal match, so no earlier
/// match can hide it, and it is masked whole: the name, the document number and
/// the dates all sit inside it. The scan is one regex pass (linear).
static MRZ_LINE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9<]{28,}").expect("mrz line regex compiles"));
/// The shortest run read as an MRZ line (TD1 is 30 chars; two may be lost to OCR).
const MRZ_LINE_MIN: usize = 28;
/// The longest data row, in characters (TD3 and MRV-A).
const MRZ_ROW_MAX: usize = 44;
/// The most tokens a data row spans: OCR may split it at blanks.
const MRZ_MAX_TOKENS: usize = 6;
/// The most spaces between two tokens of a data row.
const MRZ_MAX_GAP: usize = 3;
/// The most windows read in one token.
const MRZ_MAX_WINDOWS: usize = 4096;
/// Score of a machine-readable zone line.
pub const MRZ_LINE_SCORE: f32 = 1.0;

/// A token of a data row: letters, digits, `<`, and `«` (OCR's `<`).
static MRZ_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9<«]+").expect("mrz token regex compiles"));

static MRZ_CHECK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z0-9<]{9}[0-9]\b").expect("mrz regex compiles"));
static STRICT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z]{1,3}[0-9]{6,9}\b").expect("passport regex compiles"));
static STRICT_SEPARATED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[A-Z]{1,3}[ .\-][0-9]{6,9}\b").expect("separated passport regex compiles")
});
static BROAD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z0-9]{8,10}\b").expect("broad passport regex compiles"));

/// A passport number shaped like `1–3 letters + 6–9 digits`, with or without a
/// valid ICAO check digit.
#[derive(Clone, Copy, Debug)]
pub struct PassportMrzRecognizer {
    verified: bool,
}

impl PassportMrzRecognizer {
    /// Build the recogniser (unverified, mounted by default).
    pub fn new() -> Self {
        Self { verified: false }
    }
}

impl Default for PassportMrzRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for PassportMrzRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::PassportMrz]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let identity = |start: usize, end: usize| {
            (start < end && text.is_char_boundary(start) && text.is_char_boundary(end))
                .then_some((start, end))
        };
        self.analyze_with_source(text, text, &identity)
    }

    fn analyze_with_source(
        &self,
        text: &str,
        original: &str,
        source_bounds: &dyn Fn(usize, usize) -> Option<(usize, usize)>,
    ) -> Vec<Span> {
        // The normalised view makes Unicode digits and fullwidth letters part
        // of the shape; the OCR confusable fold stays off because a passport
        // number carries meaningful letters (P1).
        let normalized = NormalizedText::new(text, false);
        let body = normalized.text();
        let mut spans: Vec<Span> = Vec::new();
        // A whole MRZ line masks on its shape: a long run with a `<<` filler,
        // or a data row (`data_rows`).
        for found in MRZ_LINE_RE.find_iter(body) {
            if found.len() >= MRZ_LINE_MIN && found.as_str().contains("<<") {
                push(
                    &mut spans,
                    &normalized,
                    found.start(),
                    found.end(),
                    MRZ_LINE_SCORE,
                );
            }
        }
        for (start, end) in data_rows(body) {
            push(&mut spans, &normalized, start, end, MRZ_LINE_SCORE);
        }
        // A valid 7-3-1 check digit raises the score and is masked on its own.
        for found in MRZ_CHECK_RE.find_iter(body) {
            if let Some(score) = check_score(found.as_str()) {
                push(&mut spans, &normalized, found.start(), found.end(), score);
            }
        }
        // UUID delimiters and candidate ranges both map to the original text:
        // a folded view can erase a non-ASCII neighbour that is not an ASCII
        // delimiter. A cue or valid check digit remains a passport signal
        // even when the candidate lies inside a whole UUID token.
        let ids = uuid_tokens(original);
        // The strict shape masks by default. Without a cue or a valid check
        // digit, a candidate wholly inside a whole ASCII-delimited UUID is one
        // of the id's fields and can be left in clear (MRZ-UUID-OVERMASK).
        let mut ibans = None;
        for found in STRICT_RE.find_iter(body) {
            let checked = check_score(found.as_str());
            let source = normalized
                .to_original(found.start(), found.end())
                .and_then(|(start, end)| source_bounds(start, end));
            if checked.is_none() && !near_cue(body, found.start(), found.end()) {
                if let Some((start, end)) =
                    source.filter(|&(start, end)| inside_uuid(&ids, start, end))
                {
                    // Keep main's overlap result if another recognizer also
                    // reads this UUID field. This avoids exposing a previously
                    // suppressed IBAN candidate when the passport guess drops.
                    let overlaps_iban = ibans
                        .get_or_insert_with(|| IbanRecognizer::new().analyze(text))
                        .iter()
                        .any(|iban| iban.start < end && start < iban.end);
                    if !overlaps_iban {
                        continue;
                    }
                }
            }
            let score = checked.unwrap_or(STRICT_SCORE);
            push(&mut spans, &normalized, found.start(), found.end(), score);
        }
        // A separated strict shape masks too. A *space* between the prefix and
        // the digits is too weak on its own (a cued TAJ, `TAJ 123456788`, looks
        // the same), so without a passport cue that form needs a strong passport
        // signal; a hyphen or dot is unambiguous attachment and masks on sight.
        for found in STRICT_SEPARATED_RE.find_iter(body) {
            let value = found.as_str();
            if value.contains(' ')
                && !near_cue(body, found.start(), found.end())
                && !spaced_without_cue_is_passport(value)
            {
                continue;
            }
            push(
                &mut spans,
                &normalized,
                found.start(),
                found.end(),
                STRICT_SCORE,
            );
        }
        // The broad shape masks near a cue, before or after the value.
        for found in BROAD_RE.find_iter(body) {
            let value = found.as_str();
            let digits = value.chars().filter(|ch| ch.is_ascii_digit()).count();
            if digits < 5 || !near_cue(body, found.start(), found.end()) {
                continue;
            }
            let score = check_score(value).unwrap_or(BROAD_SCORE);
            push(&mut spans, &normalized, found.start(), found.end(), score);
        }
        spans.sort_by_key(|span| (span.start, span.end));
        spans.dedup_by_key(|span| (span.start, span.end));
        spans
    }

    fn name(&self) -> &'static str {
        "passport_mrz"
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

/// Whether a byte range lies wholly inside one of the sorted, non-overlapping
/// UUID tokens returned by `iban::uuid_tokens`.
fn inside_uuid(ids: &[(usize, usize)], start: usize, end: usize) -> bool {
    let index = ids.partition_point(|&(_, uuid_end)| uuid_end <= start);
    ids.get(index)
        .is_some_and(|&(uuid_start, uuid_end)| uuid_start <= start && end <= uuid_end)
}

fn push(spans: &mut Vec<Span>, normalized: &NormalizedText, start: usize, end: usize, score: f32) {
    if let Some((start, end)) = normalized.to_original(start, end) {
        spans.push(Span::new(
            EntityKind::PassportMrz,
            start,
            end,
            score,
            "passport_mrz",
        ));
    }
}

/// A check digit of a layout: the `(start, end)` payload fields it covers,
/// then its position.
type Check = (&'static [(usize, usize)], usize);

/// TD3 line 2 (44): document, birth, expiry, personal number, composite.
const TD3_CHECKS: &[Check] = &[
    (&[(0, 9)], 9),
    (&[(13, 19)], 19),
    (&[(21, 27)], 27),
    (&[(28, 42)], 42),
    (&[(0, 10), (13, 20), (21, 43)], 43),
];
/// TD2 line 2 (36): document, birth, expiry, composite.
const TD2_CHECKS: &[Check] = &[
    (&[(0, 9)], 9),
    (&[(13, 19)], 19),
    (&[(21, 27)], 27),
    (&[(0, 10), (13, 20), (21, 35)], 35),
];
/// A visa row (MRV-A 44, MRV-B 36): document, birth and expiry only.
const MRV_CHECKS: &[Check] = &[(&[(0, 9)], 9), (&[(13, 19)], 19), (&[(21, 27)], 27)];
/// TD1 line 2 (30): birth and expiry. Its composite also covers line 1, which
/// a row alone does not hold.
const TD1_LINE2_CHECKS: &[Check] = &[(&[(0, 6)], 6), (&[(8, 14)], 14)];
/// TD1 line 1 (30): document.
const TD1_LINE1_CHECKS: &[Check] = &[(&[(5, 14)], 14)];
/// The issuers a TD1 line 1 may carry at positions 2-4 (ICAO 9303 part 3): ISO
/// 3166-1 alpha-3, then the ICAO codes (`D<<` Germany, the EU, British,
/// UN and other organisations, the stateless `XX*`, Kosovo, the former
/// Netherlands Antilles and the `UTO` specimen). A code the 7-3-1 check
/// passes by chance (one in ten) is no ID card line without one of them.
const TD1_ISSUERS: &str = "\
    ABW AFG AGO AIA ALA ALB AND ARE ARG ARM ASM ATA ATF ATG AUS AUT AZE BDI BEL BEN BES BFA BGD \
    BGR BHR BHS BIH BLM BLR BLZ BMU BOL BRA BRB BRN BTN BVT BWA CAF CAN CCK CHE CHL CHN CIV CMR \
    COD COG COK COL COM CPV CRI CUB CUW CXR CYM CYP CZE DEU DJI DMA DNK DOM DZA ECU EGY ERI ESH \
    ESP EST ETH FIN FJI FLK FRA FRO FSM GAB GBR GEO GGY GHA GIB GIN GLP GMB GNB GNQ GRC GRD GRL \
    GTM GUF GUM GUY HKG HMD HND HRV HTI HUN IDN IMN IND IOT IRL IRN IRQ ISL ISR ITA JAM JEY JOR \
    JPN KAZ KEN KGZ KHM KIR KNA KOR KWT LAO LBN LBR LBY LCA LIE LKA LSO LTU LUX LVA MAC MAF MAR \
    MCO MDA MDG MDV MEX MHL MKD MLI MLT MMR MNE MNG MNP MOZ MRT MSR MTQ MUS MWI MYS MYT NAM NCL \
    NER NFK NGA NIC NIU NLD NOR NPL NRU NZL OMN PAK PAN PCN PER PHL PLW PNG POL PRI PRK PRT PRY \
    PSE PYF QAT REU ROU RUS RWA SAU SDN SEN SGP SGS SHN SJM SLB SLE SLV SMR SOM SPM SRB SSD STP \
    SUR SVK SVN SWE SWZ SXM SYC SYR TCA TCD TGO THA TJK TKL TKM TLS TON TTO TUN TUR TUV TWN TZA \
    UGA UKR UMI URY USA UZB VAT VCT VEN VGB VIR VNM VUT WLF WSM YEM ZAF ZMB ZWE D<< EUE GBD GBN \
    GBO GBP GBS UNA UNK UNO XOM XXA XXB XXC XXX RKS ANT XBA XCC XCE XCO XDC XEC XES XIM XMP XPO \
    UTO";

/// The data rows of `body` with no `<<` filler, as byte ranges of `body`. A row
/// is the exact length of its layout (TD1 30, TD2 36, TD3 44, visa 36 or 44)
/// once its blanks are dropped: whole tokens of letters, digits, `<` and `«`
/// (OCR's `<`) joined by at most [`MRZ_MAX_GAP`] spaces, at most
/// [`MRZ_MAX_TOKENS`] tokens, never across a line break. The range runs from the
/// first character of the first token to the last of the last, spaces
/// included. Linear: each token starts at most [`MRZ_MAX_TOKENS`] windows, and
/// only a window of a layout's exact length is read.
fn data_rows(body: &str) -> Vec<(usize, usize)> {
    let tokens: Vec<(usize, usize)> = MRZ_TOKEN_RE
        .find_iter(body)
        .map(|found| (found.start(), found.end()))
        .collect();
    let mut rows = Vec::new();
    let mut row: Vec<u8> = Vec::with_capacity(MRZ_ROW_MAX + 1);
    for (first, &(start, _)) in tokens.iter().enumerate() {
        row.clear();
        for (at, &(from, to)) in tokens[first..].iter().enumerate().take(MRZ_MAX_TOKENS) {
            if at > 0 {
                let gap = &body[tokens[first + at - 1].1..from];
                if gap.len() > MRZ_MAX_GAP || !gap.bytes().all(|b| b == b' ') {
                    break;
                }
            }
            row.extend(body[from..to].chars().map(read_char));
            if row.len() > MRZ_ROW_MAX {
                break;
            }
            if at > 0 && matches!(row.len(), 30 | 36 | 44) && is_data_row(&row, true) {
                rows.push((start, to));
                break;
            }
        }
    }
    for &(from, to) in &tokens {
        token_rows(body, from, to, &mut rows);
    }
    rows
}

/// A row as a byte: `«` is OCR's `<`.
fn read_char(ch: char) -> u8 {
    if ch == '«' {
        b'<'
    } else {
        ch as u8
    }
}

/// The rows inside one token, a row alone or glued to text or to other rows
/// with no separator (`xX4R2…18y`, two rows end to end): every window of a
/// layout's width (44, 36, 30) that is a data row, as its own byte range, so
/// the text around it is left as it was. A cheap shape test ([`plausible`])
/// keeps a window from being read, and at most [`MRZ_MAX_WINDOWS`] windows of a
/// token are read: linear in the token.
fn token_rows(body: &str, from: usize, to: usize, rows: &mut Vec<(usize, usize)>) {
    let token = &body[from..to];
    let chars: Vec<(usize, char)> = token.char_indices().collect();
    if chars.len() < 30 {
        return;
    }
    let bytes: Vec<u8> = chars
        .iter()
        .map(|&(_, ch)| read_char(ch).to_ascii_uppercase())
        .collect();
    let mut read = 0;
    for width in [44, 36, 30] {
        for first in 0..(bytes.len() + 1).saturating_sub(width) {
            let row = &bytes[first..first + width];
            if !plausible(row) {
                continue;
            }
            read += 1;
            if read > MRZ_MAX_WINDOWS {
                return;
            }
            if is_data_row(row, width == bytes.len()) {
                let end = chars.get(first + width).map_or(token.len(), |&(at, _)| at);
                rows.push((from + chars[first].0, from + end));
            }
        }
    }
}

/// Whether the upper-case `row` (30, 36 or 44) has the shape of a data row, a
/// letter OCR may read for a digit counting as a digit: no allocation, and
/// almost every window of ordinary text stops at its first test.
fn plausible(row: &[u8]) -> bool {
    let digit = |c: u8| c.is_ascii_digit() || matches!(c, b'O' | b'I' | b'L');
    let digits = |r: Range<usize>| row[r].iter().all(|&c| digit(c));
    let letters = |r: Range<usize>| row[r].iter().all(|&c| c.is_ascii_uppercase() || c == b'<');
    let sex = |at: usize| matches!(row[at], b'M' | b'F' | b'X' | b'<');
    match row.len() {
        44 | 36 => letters(10..13) && sex(20) && digit(row[9]) && digits(13..20) && digits(21..28),
        _ => {
            digits(0..7) && sex(7) && digits(8..15) && letters(15..18)
                || matches!(row[0], b'I' | b'A' | b'C') && letters(1..5) && digit(row[14])
        }
    }
}

/// Whether `row` (characters of a row of 30, 36 or 44, `«` already `<`) is an
/// MRZ data row. It is read upper-cased; the letters OCR reads for a digit
/// (`O`, `I`, `l`) in the numeric fields and check positions are read as that
/// digit.
///
/// `whole` is false for a window inside a longer token.
///
/// A row holds only if every check digit of its layout validates, however clean
/// it looks: TD3 document, birth, expiry, personal number and composite; TD2
/// document, birth, expiry and composite; a visa row (MRV-A, MRV-B) document,
/// birth and expiry, with a `<` in its optional data; TD1 line 1 document; TD1
/// line 2 birth and expiry. A shape alone is no row: a code that fails its
/// checks is main's, not masked whole. The document number and the optional
/// data are tried as written and with OCR letters read as digits, the optional
/// data also with `K` and `C` read as `<`.
fn is_data_row(row: &[u8], whole: bool) -> bool {
    let mut b = row.to_ascii_uppercase();
    let nation =
        |b: &[u8], r: Range<usize>| b[r].iter().all(|c| c.is_ascii_uppercase() || *c == b'<');
    let digits = |b: &[u8], r: Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let sex = |b: &[u8], at: usize| matches!(b[at], b'M' | b'F' | b'X' | b'<');
    match b.len() {
        44 | 36 => {
            // Numeric: document check, birth with its check, expiry with its check.
            let (long, optional_end) = if b.len() == 44 {
                (TD3_CHECKS, 42)
            } else {
                (TD2_CHECKS, 35)
            };
            digits_read(&mut b, [9..10, 13..20, 21..28].into_iter().flatten());
            if !(nation(&b, 10..13) && digits(&b, 13..19) && sex(&b, 20) && digits(&b, 21..27))
                || !b[9].is_ascii_digit()
            {
                return false;
            }
            // A visa row's optional data runs to the end of the row.
            let visa = variants(&b, 0..9, 28..b.len());
            // The personal-number and composite check positions are numeric too.
            let tail = b.len() - 1;
            digits_read(&mut b, [optional_end, tail]);
            variants(&b, 0..9, 28..optional_end)
                .iter()
                .any(|variant| holds(variant, long))
                || visa
                    .iter()
                    .any(|v| holds(v, MRV_CHECKS) && v[28..].contains(&b'<'))
        }
        30 => {
            let mut line2 = b.clone();
            digits_read(&mut line2, (0..7).chain(8..15));
            if digits(&line2, 0..6)
                && sex(&line2, 7)
                && digits(&line2, 8..14)
                && nation(&line2, 15..18)
                && line2[6].is_ascii_digit()
                && line2[14].is_ascii_digit()
                && holds(&line2, TD1_LINE2_CHECKS)
            {
                return true;
            }
            // TD1 line 1 has the weakest evidence (one check digit): inside a longer
            // token it must show a filler `<`.
            // ICAO 9303: an `I`, `A` or `C` document code, then a letter or `<`,
            // then a known issuer.
            let issuer = |b: &[u8]| {
                TD1_ISSUERS
                    .split_whitespace()
                    .any(|c| c.as_bytes() == &b[2..5])
            };
            if !(matches!(b[0], b'I' | b'A' | b'C') && nation(&b, 1..2) && issuer(&b))
                || !whole && !b.contains(&b'<')
            {
                return false;
            }
            digits_read(&mut b, [14]);
            if !b[14].is_ascii_digit() {
                return false;
            }
            let digit_count = |b: &[u8]| b.iter().filter(|c| c.is_ascii_digit()).count();
            variants(&b, 5..14, 15..15)
                .iter()
                .any(|v| digit_count(v) >= 6 && holds(v, TD1_LINE1_CHECKS))
        }
        _ => false,
    }
}

/// Read the letters OCR mistakes for a digit (`O` as `0`, `I` and `L` as `1`)
/// at the positions `at` of `b` as digits; how many were read.
fn digits_read(b: &mut [u8], at: impl IntoIterator<Item = usize>) -> usize {
    let mut read = 0;
    for at in at {
        let digit = match b[at] {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            _ => continue,
        };
        b[at] = digit;
        read += 1;
    }
    read
}

/// The readings of `b` to try: its `document` number as written or with OCR
/// letters read as digits, crossed with its `optional` data as written, with
/// letters read as digits, with `K` and `C` read as `<`, and both.
fn variants(b: &[u8], document: Range<usize>, optional: Range<usize>) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(8);
    for doc in [false, true] {
        for opt in 0..4 {
            let mut v = b.to_vec();
            if doc {
                digits_read(&mut v, document.clone());
            }
            if opt & 1 == 1 {
                digits_read(&mut v, optional.clone());
            }
            if opt & 2 == 2 {
                for c in &mut v[optional.clone()] {
                    if matches!(*c, b'K' | b'C') {
                        *c = b'<';
                    }
                }
            }
            out.push(v);
        }
    }
    out
}

/// Whether every check digit of `checks` is valid on `b`. A `<` check digit is
/// valid only on an all-`<` payload (an empty optional field); the document,
/// birth and expiry checks are digits, never `<`.
fn holds(b: &[u8], checks: &[Check]) -> bool {
    checks.iter().all(|(from, at)| {
        let payload: Vec<u8> = from
            .iter()
            .flat_map(|&(s, e)| b[s..e].iter().copied())
            .collect();
        let payload = std::str::from_utf8(&payload).unwrap_or("");
        match b[*at] {
            b'<' => ![9, 19, 27].contains(at) && payload.bytes().all(|c| c == b'<'),
            digit @ b'0'..=b'9' => passport_mrz_ok(payload, digit - b'0'),
            _ => false,
        }
    })
}

/// The 7-3-1 score of a ten-character `payload + check digit` value, if valid.
///
/// The value may be lower case (the rule is case-insensitive), so it is
/// upper-cased before the check.
fn check_score(value: &str) -> Option<f32> {
    if value.len() != 10 {
        return None;
    }
    let upper = value.to_ascii_uppercase();
    let (payload, check) = upper.split_at(9);
    let digit = check.bytes().next().map(|byte| byte - b'0');
    let shaped = payload.chars().any(|ch| ch.is_ascii_digit())
        && payload.chars().any(|ch| ch.is_ascii_uppercase());
    if shaped && digit.is_some_and(|digit| passport_mrz_ok(payload, digit)) {
        Some(1.0)
    } else {
        None
    }
}

/// Whether a space-separated strict shape is a passport without a cue.
///
/// The cue-less spaced form is masked on shape alone for *every* 1–3 letter
/// prefix and 7–9 digits (P2: `E 12345678` and `AB 1234567` used to leak), so a
/// bare OCR line or a CSV cell no longer depends on a three-letter prefix.
/// Two short exceptions stay clear because the prefix is a word with another
/// meaning: `ISO` heads an international-standard number, and the
/// [`BUSINESS_PREFIXES`] head an order or article reference. A prefix that cues
/// another rule (`TAJ`) is left to that rule. A de-spaced value whose ICAO
/// 7-3-1 check digit validates is still the strongest signal and is masked.
fn spaced_without_cue_is_passport(value: &str) -> bool {
    let Some((prefix, digits)) = value.split_once(' ') else {
        return false;
    };
    if NON_PASSPORT_PREFIXES
        .iter()
        .chain(BUSINESS_PREFIXES.iter())
        .any(|known| prefix.eq_ignore_ascii_case(known))
    {
        return false;
    }
    // (a) A valid 7-3-1 check digit is the strongest passport signal.
    let de_spaced: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    if check_score(&de_spaced).is_some() {
        return true;
    }
    // (b) The cue-less shape `[A-Z]{1,3} [0-9]{7,9}` masks for every prefix
    // length; a 6-digit tail is too weak to stand alone.
    (1..=3).contains(&prefix.len()) && (7..=9).contains(&digits.len())
}

/// Whether a passport cue appears within [`CUE_WINDOW`] characters before *or*
/// after the `start..end` value.
fn near_cue(text: &str, start: usize, end: usize) -> bool {
    let begin = text[..start]
        .char_indices()
        .rev()
        .nth(CUE_WINDOW)
        .map(|(index, _)| index)
        .unwrap_or(0);
    let finish = text[end..]
        .char_indices()
        .nth(CUE_WINDOW)
        .map(|(index, _)| end + index)
        .unwrap_or(text.len());
    let window = text[begin..finish].to_lowercase();
    CUES.iter().any(|cue| window.contains(cue))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        PassportMrzRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn a_machine_readable_zone_line_is_masked_whole() {
        // FAKE: the ICAO 9303 TD3 specimen and a TD1-style German specimen,
        // with no passport cue nearby.
        let td3 = "scan:\nP<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10";
        let found = hits(td3);
        for line in [
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
            "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
        ] {
            assert!(
                found.iter().any(|hit| hit.contains(line)),
                "{line} is not masked whole: {found:?}"
            );
        }
        let de = "C01X00T478D<<6408125F2702283<<<<<<<<<<<<<<<4\nMUSTERMANN<<ERIKA<<<<<<<<<<<<<<";
        let found = hits(de);
        for line in [
            "C01X00T478D<<6408125F2702283<<<<<<<<<<<<<<<4",
            "MUSTERMANN<<ERIKA<<<<<<<<<<<<<<",
        ] {
            assert!(
                found.iter().any(|hit| hit.contains(line)),
                "{line}: {found:?}"
            );
        }
        // A short `<<` run, a shell heredoc or generics stay clear.
        assert!(hits("cat <<EOF and Vec<Vec<u8>>").is_empty());
    }

    #[test]
    fn a_data_line_with_no_filler_is_masked_whole_when_its_checks_hold() {
        let is_data_line = |row: &str| !data_rows(row).is_empty();
        let td3 = "X4R2T9M716UTO8703145M31092255820411773094106";
        let td3b = "KD7Q0P2Z80UTO9201051F29061177103992645812096";
        let td1 = "IDUTOR8M4K2T075395820174461823";
        let td1_2 = "8703145M3109225UTO581041177364";
        // A row may also give a shorter hit inside itself (a 36-character prefix
        // whose composite check holds by chance): it lies within the row.
        let whole = |text: &str, rows: &[&str]| {
            let found = hits(text);
            rows.iter().all(|row| found.iter().any(|hit| hit == row))
                && found
                    .iter()
                    .all(|hit| rows.iter().any(|row| row.contains(hit.as_str())))
        };
        assert!(whole(&format!("MRZ\n{td3}"), &[td3]));
        assert!(whole(td1, &[td1]));
        assert!(whole(td1_2, &[td1_2]));
        // Two rows glued with no separator, and a row attached to text: each row
        // is masked, the text is not.
        assert!(whole(&format!("{td3}{td3b}"), &[td3, td3b]));
        assert!(whole(&format!("x{td3}y"), &[td3]));
        // One character short: not a layout, so main's masks only.
        for short in [&td1[1..], &td1_2[..29]] {
            assert!(!is_data_line(short), "{short}");
        }
        // A shape with a wrong check digit, a `<` on a document check digit, or
        // a wrong one once read, is no row (its first 36 characters may still be
        // one, a TD2 row whose composite check holds by chance).
        for no_row in [
            "AZQVODDGMSGA3C9A<BYZ2N135VE7JH",
            "X4R2T9M716UTO8703145M31092255820411773094107",
            "AB1234567<UTO8703042F30091521234567890123458",
            "X4R2T9M71oUTO8703145M31092255820411773094106",
        ] {
            assert!(!hits(no_row).iter().any(|hit| hit == no_row), "{no_row}");
        }
        assert!(hits("3F2A9C41B07D58E6A1C3F2A9C41B07D58E6A1C3FA").is_empty());
    }

    #[test]
    fn masks_separated_unicode_and_case_insensitive_passports() {
        // P1: a single space, hyphen or dot between the prefix and the digits,
        // on the normalised view and case-insensitively.
        assert_eq!(hits("Passport no QXZ 1234567"), vec!["QXZ 1234567"]);
        assert_eq!(hits("جواز السفر QXZ١٢٣٤٥٦٧"), vec!["QXZ١٢٣٤٥٦٧"]);
        assert_eq!(hits("passeport qxz1234567"), vec!["qxz1234567"]);
        assert_eq!(hits("paspoort QXZ-1234567"), vec!["QXZ-1234567"]);
        assert_eq!(hits("passeport l898902c36"), vec!["l898902c36"]);
        // The fullwidth dot and Persian digits fold like their ASCII forms.
        assert_eq!(
            hits("passeport QXZ．１２３４５６７"),
            vec!["QXZ．１２３４５６７"]
        );
        // Two separators are not the passport shape.
        assert!(hits("QXZ  1234567").is_empty());
    }

    #[test]
    fn valid_and_invalid_vectors() {
        let recognizer = PassportMrzRecognizer::new();
        assert_eq!(hits("passport L898902C36"), vec!["L898902C36"]);
        // No cue and no strict shape: only a valid check digit would mask it.
        assert!(hits("L898902C35").is_empty());
        assert!(!recognizer.verified());
        assert!(recognizer.enabled_by_default());
    }

    #[test]
    fn strict_shape_masks_without_a_cue_and_raises_with_a_check_digit() {
        assert_eq!(hits("reference QXZ1000001"), vec!["QXZ1000001"]);
        let spans = PassportMrzRecognizer::new().analyze("QXZ1000001");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].score, STRICT_SCORE);
    }

    #[test]
    fn broad_shape_only_masks_near_a_cue() {
        // `A1B2C3D4E5` is not the strict shape, so only a cue widens it.
        assert!(hits("A1B2C3D4E5").is_empty());
        assert_eq!(
            hits("passeport A1B2C3D4E5"),
            vec!["A1B2C3D4E5"],
            "cued broad shape missed"
        );
        assert_eq!(hits("P<FRADUPONT A1B2C3D4E5"), vec!["A1B2C3D4E5"]);
    }

    #[test]
    fn spaced_form_masks_without_a_cue_for_every_prefix_length() {
        // P2: a bare OCR line with no cue at all, for 1, 2 and 3 letter
        // prefixes (`E 12345678` and `AB 1234567` used to leak).
        assert_eq!(hits("QXZ 1234567"), vec!["QXZ 1234567"]);
        assert_eq!(hits("E 12345678"), vec!["E 12345678"]);
        assert_eq!(hits("AB 1234567"), vec!["AB 1234567"]);
        // A 6-digit tail is too weak to stand alone.
        assert!(hits("ISO 123456").is_empty());
        // The two exceptions stay clear: an ISO prefix and a business prefix.
        assert!(hits("ISO 1234567").is_empty());
        assert!(hits("REF 1234567").is_empty());
        // (a) a de-spaced value whose 7-3-1 check digit validates.
        assert_eq!(hits("L 123456781"), vec!["L 123456781"]);
        // A prefix that cues another rule is left to that rule.
        assert!(hits("TAJ 123456788").is_empty());
    }

    #[test]
    fn cue_window_looks_after_the_value_too() {
        // The cue may follow the value within the window (P3).
        assert_eq!(hits("A1B2C3D4E5 passeport"), vec!["A1B2C3D4E5"]);
        // A cue beyond the 64-character window does not widen the shape.
        let mut distant = String::from("A1B2C3D4E5 ");
        distant.push_str(&"x".repeat(CUE_WINDOW));
        distant.push_str(" passeport");
        assert!(hits(&distant).is_empty());
    }

    #[test]
    fn a_cued_bad_check_digit_is_still_masked() {
        assert_eq!(
            hits("passeport L898902C35"),
            vec!["L898902C35"],
            "a typo near a passport cue leaked"
        );
    }

    #[test]
    fn rejects_all_letter_and_all_digit_shaped_values() {
        assert!(hits("ABCDEFGHI6").is_empty());
        assert!(hits("1234567891").is_empty());
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = PassportMrzRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::PassportMrz]);
        assert_eq!(recognizer.name(), "passport_mrz");
    }
}
