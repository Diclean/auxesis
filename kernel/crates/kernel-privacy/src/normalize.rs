//! Shared normalisation layer for scanning (P2-1, P2-2, P2-3).
//!
//! The deterministic recognisers scan a *normalised* view of the input so that
//! a value written with Unicode digits, exotic spaces, dashes or OCR noise is
//! still found, while every span is reported on the original byte offsets.
//! The layer:
//!
//! * maps every Unicode decimal digit (`Nd`) to its ASCII digit, so fullwidth
//!   and Arabic-Indic numbers count as digits;
//! * folds Unicode spaces (NBSP, U+202F, U+2009, …) to ASCII space and the
//!   dash range U+2010–U+2015 plus U+2212 to ASCII `-`;
//! * folds the whole fullwidth ASCII block (letters, digits, punctuation and
//!   the commercial `＠`) to its ASCII form, so `ａｐｐ １０.０.０.５` scans as
//!   `app 10.0.0.5` and `１９２．１６８．０．１` scans as `192.168.0.1`;
//! * folds the ideographic full stop `。` to `.` when it sits between two
//!   digits, so a CJK sentence-ending mark never turns a number into a date;
//! * strips zero-width characters (ZWSP/ZWNJ/ZWJ/WORD JOINER/BOM/soft hyphen);
//! * folds a run of separators that holds a line break or tab (`\n`, `\r\n`,
//!   `\r`, `\t`, with or without spaces around it) to one ASCII space, so an
//!   IBAN or phone number wrapped across lines still scans as one value. A run
//!   folds only within its caps (at most two line breaks and eight separator
//!   characters in all); a longer run becomes a hard boundary that no
//!   identifier crosses, so masking can never swallow a long blank region. The
//!   run's original bytes stay inside the span's offsets. A run that holds a
//!   zero-width character, even without a line break, is capped the same way;
//! * removes a quoted-printable soft break (an `=`, optional blanks, then `\r\n`,
//!   `\r` or `\n`) before the folds, so the two sides join with nothing between
//!   them and a value a mail client wrapped still scans as one value;
//! * optionally folds single OCR confusables (`O`/`o` → `0`, `l`/`I` → `1`)
//!   that sit between or immediately beside digits, so a whole letter word is
//!   never rewritten.

use std::cell::RefCell;
use std::sync::Arc;

use unicode_normalization::UnicodeNormalization;

use crate::contacts::fold::{homoglyph, is_cyrillic, is_greek};
use crate::decode;

/// The most line breaks a separator run may hold and still fold to one space.
const MAX_FOLDED_BREAKS: usize = 2;

/// The most separator characters a run may hold and still fold to one space.
const MAX_FOLDED_RUN: usize = 8;

/// What a run too long to fold becomes in the normalised text. A NUL is no
/// digit, letter, space or punctuation any recogniser accepts, so no
/// identifier can cross it.
const RUN_BOUNDARY: char = '\u{0}';

/// A scanned view of a text plus a map from normalised byte offsets back to the
/// original byte offsets. Cloning shares the view.
#[derive(Clone)]
pub struct NormalizedText {
    text: Arc<String>,
    /// Byte offset of each normalised char; empty when offsets are identity.
    char_starts: Arc<[usize]>,
    /// Original `(start, end)` bounds of each normalised char; empty when identity.
    orig_bounds: Arc<[(usize, usize)]>,
    /// `text` is the input unchanged and every byte maps to itself, so
    /// [`NormalizedText::to_original`] is the identity and no map is needed.
    identity: bool,
    /// All normalised chars are one byte, so a byte offset is also a char
    /// index and `char_starts` is empty.
    compact: bool,
}

/// One scan: its text (shared with an identity view, reusable) and two views.
struct Scan {
    source: Arc<String>,
    views: [Option<NormalizedText>; 2],
}

/// The scans on this thread; `depth` counts live ones, the rest are spare slots.
struct Shared {
    scans: Vec<Scan>,
    depth: usize,
}

thread_local! {
    static SHARED: RefCell<Shared> = const {
        RefCell::new(Shared { scans: Vec::new(), depth: 0 })
    };
}

/// While alive, every [`NormalizedText::new`] of exactly this text shares one
/// view per `ocr` flag, so the recognisers of a scan normalise the text twice,
/// not once each (K-REGISTRY-PERF: two dozen whole-text passes were most of a
/// megabyte's scan). A view is a pure function of the text and the flag, so a
/// shared one is the value a fresh build returns. Dropping the guard (or a
/// panic unwinding past it) forgets the text and its views.
///
/// A scan that runs while a non-main thread is tearing down its thread-locals
/// — for example, another thread-local's `Drop` invoking the registry — calls
/// into `SHARED` after the storage is gone. `try_with` returns an `AccessError`
/// in that window, so the guard silently stays unregistered and its `Drop`
/// stays a no-op; every call falls back to a fresh build whose output is
/// byte-identical to the cached one (K-REGISTRY-PERF r1 fix for NO SEAL P2).
pub(crate) struct SharedViews(bool);

impl SharedViews {
    pub(crate) fn new(text: &str) -> Self {
        let registered = SHARED
            .try_with(|shared| {
                let mut shared = shared.borrow_mut();
                let depth = shared.depth;
                if depth < shared.scans.len() {
                    // Reuse the slot and its source allocation; a caller still
                    // holding a view keeps the old source alive, so replace it.
                    let scan = &mut shared.scans[depth];
                    scan.views = [None, None];
                    match Arc::get_mut(&mut scan.source) {
                        Some(source) => {
                            source.clear();
                            source.push_str(text);
                        }
                        None => scan.source = Arc::new(text.to_owned()),
                    }
                } else {
                    shared.scans.push(Scan {
                        source: Arc::new(text.to_owned()),
                        views: [None, None],
                    });
                }
                shared.depth += 1;
            })
            .is_ok();
        Self(registered)
    }
}

impl Drop for SharedViews {
    fn drop(&mut self) {
        if !self.0 {
            // Thread-local storage was already gone when the guard was built,
            // so nothing was pushed. Touching SHARED now would panic, and a
            // drop is the one place a panic is silently unobservable.
            return;
        }
        let _ = SHARED.try_with(|shared| {
            let mut shared = shared.borrow_mut();
            if shared.depth > 0 {
                let depth = shared.depth - 1;
                shared.depth = depth;
                // Release the views; the slot's source stays for reuse.
                shared.scans[depth].views = [None, None];
            }
        });
    }
}

impl NormalizedText {
    /// Build the normalised view. `ocr` enables the digit-run confusable fold.
    pub fn new(text: &str, ocr: bool) -> Self {
        let slot = usize::from(ocr);
        // The cache lives in a thread-local. While the current thread's
        // thread-locals are being torn down (for example inside another
        // thread-local's `Drop`) `try_with` fails with `AccessError`; fall
        // back to a fresh build whose output is byte-identical to the cached
        // view, so the recognition result never depends on the cache.
        let found = SHARED.try_with(|shared| {
            let shared = shared.borrow();
            let depth = shared.depth;
            if depth == 0 {
                return None;
            }
            let scan = shared.scans.get(depth - 1)?;
            if scan.source.as_str() != text {
                return None;
            }
            Some((scan.views[slot].clone(), Arc::clone(&scan.source)))
        });
        match found {
            Err(_) | Ok(None) => Self::build(text, ocr),
            Ok(Some((Some(view), _))) => view,
            Ok(Some((None, source))) => {
                let view = Self::build_shared(&source, ocr);
                let _ = SHARED.try_with(|shared| {
                    let mut shared = shared.borrow_mut();
                    let depth = shared.depth;
                    if let Some(scan) = shared.scans.get_mut(depth.wrapping_sub(1)) {
                        if Arc::ptr_eq(&scan.source, &source) {
                            scan.views[slot] = Some(view.clone());
                        }
                    }
                });
                view
            }
        }
    }

    /// The view of `text`: identity, else the ASCII or general builder.
    fn build(text: &str, ocr: bool) -> Self {
        if is_identity(text, ocr) {
            return Self::identity(Arc::new(text.to_owned()));
        }
        if text.is_ascii() {
            return Self::build_ascii(text, ocr);
        }
        Self::build_slow(text, ocr)
    }

    /// [`NormalizedText::build`] sharing the scan's source for an identity view.
    fn build_shared(source: &Arc<String>, ocr: bool) -> Self {
        if is_identity(source, ocr) {
            return Self::identity(Arc::clone(source));
        }
        if source.is_ascii() {
            return Self::build_ascii(source, ocr);
        }
        Self::build_slow(source, ocr)
    }

    fn identity(text: Arc<String>) -> Self {
        Self {
            text,
            char_starts: Arc::from(Vec::new()),
            orig_bounds: Arc::from(Vec::new()),
            identity: true,
            compact: true,
        }
    }

    /// The ASCII view: one byte per char, so `char_starts` is implicit.
    fn build_ascii(text: &str, ocr: bool) -> Self {
        let bytes = text.as_bytes();
        if has_soft_break(bytes) {
            return Self::build_slow(text, ocr);
        }
        let mut normalized: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut orig_bounds: Vec<(usize, usize)> = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if !is_ascii_separator(bytes[index]) {
                normalized.push(bytes[index]);
                orig_bounds.push((index, index + 1));
                index += 1;
                continue;
            }
            let start = index;
            while index < bytes.len() && is_ascii_separator(bytes[index]) {
                index += 1;
            }
            let group = &bytes[start..index];
            if group.iter().copied().any(is_ascii_break_or_tab) {
                normalized.push(if ascii_run_folds(group) { b' ' } else { 0 });
                orig_bounds.push((start, index));
            } else {
                for (at, &byte) in bytes[start..index].iter().enumerate() {
                    normalized.push(byte);
                    orig_bounds.push((start + at, start + at + 1));
                }
            }
        }
        if ocr {
            for at in 0..normalized.len() {
                if matches!(normalized[at], b'O' | b'o' | b'l' | b'I')
                    && ocr_folds_at(&normalized, at)
                {
                    normalized[at] = match normalized[at] {
                        b'O' | b'o' => b'0',
                        _ => b'1',
                    };
                }
            }
        }
        Self {
            text: Arc::new(String::from_utf8(normalized).expect("ASCII view")),
            char_starts: Arc::from(Vec::new()),
            orig_bounds: orig_bounds.into(),
            identity: false,
            compact: true,
        }
    }

    fn build_slow(text: &str, ocr: bool) -> Self {
        let source = without_soft_breaks(text);
        let mut chars: Vec<char> = Vec::with_capacity(source.len());
        let mut orig_bounds: Vec<(usize, usize)> = Vec::with_capacity(source.len());
        let mut index = 0;
        while index < source.len() {
            // A run of separator characters is scanned once, so a long run of
            // plain spaces costs linear time (one pass per run, not per char).
            let run = separator_run_len(&source[index..]);
            let span = run.max(1);
            let group = &source[index..index + span];
            let breaks = group.iter().any(|&(_, ch)| is_line_break_or_tab(ch));
            // A zero-width character counts toward the cap too, so an invisible
            // run longer than the cap is a boundary even without a line break.
            let invisible = span > MAX_FOLDED_RUN && group.iter().any(|&(_, ch)| is_zero_width(ch));
            if run > 0 && (breaks || invisible) {
                // A line break, a tab or an over-long invisible run is one
                // separator: a run within the caps becomes a single space, a
                // longer one a hard boundary. Either way its original bytes
                // (every `\r`, `\n`, tab, space and invisible character in it)
                // stay in the span.
                let (first, _) = group[0];
                let (last, last_ch) = group[span - 1];
                chars.push(if run_folds(group) { ' ' } else { RUN_BOUNDARY });
                orig_bounds.push((first, last + last_ch.len_utf8()));
            } else {
                for &(offset, ch) in group {
                    if let Some(mapped) = normalize_char(ch) {
                        chars.push(mapped);
                        orig_bounds.push((offset, offset + ch.len_utf8()));
                    }
                }
            }
            index += span;
        }
        fold_ideographic_stop(&mut chars);
        if ocr {
            fold_ocr_confusables(&mut chars);
        }
        let mut normalized = String::with_capacity(chars.len());
        let mut char_starts = Vec::with_capacity(chars.len());
        for ch in &chars {
            char_starts.push(normalized.len());
            normalized.push(*ch);
        }
        Self {
            text: Arc::new(normalized),
            char_starts: char_starts.into(),
            orig_bounds: orig_bounds.into(),
            identity: false,
            compact: false,
        }
    }

    /// The normalised text to scan.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Map a byte range in the normalised text back to original byte offsets.
    ///
    /// Returns `None` when the range is empty, out of bounds or not on a char
    /// boundary. Zero-width characters stripped inside the range are included
    /// in the original bounds, so masking covers them too.
    pub fn to_original(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        if start >= end || end > self.text.len() {
            return None;
        }
        if !self.text.is_char_boundary(start) || !self.text.is_char_boundary(end) {
            return None;
        }
        if self.identity {
            return Some((start, end));
        }
        let (first, after) = if self.compact {
            (start, end)
        } else {
            (
                self.char_starts.partition_point(|offset| *offset < start),
                self.char_starts.partition_point(|offset| *offset < end),
            )
        };
        if first >= after {
            return None;
        }
        let (orig_start, _) = self.orig_bounds[first];
        let (_, orig_end) = self.orig_bounds[after - 1];
        if orig_start >= orig_end {
            return None;
        }
        Some((orig_start, orig_end))
    }

    /// The folded views the registry scans besides the text itself (NORM-1), so
    /// a value written with look-alike, full-width, mathematical or invisible
    /// characters is found by every recogniser, ASCII-only ones included:
    ///
    /// * invisible characters (ZWSP, ZWJ, WORD JOINER, BOM, soft hyphen) drop; a
    ///   run of more than [`MAX_FOLDED_RUN`] is a hard boundary;
    /// * Unicode digits, dashes, full-width letters and the mathematical and
    ///   letter-like alphanumerics (`𝐀`, `𝟏`, `ℎ`) read as ASCII;
    /// * full-width punctuation (`＠`, `：`, `．`) reads as ASCII only beside an
    ///   ASCII letter or digit, so Chinese prose keeps its own punctuation;
    /// * a Cyrillic or Greek look-alike (`о`, `а`, `ѕ`, `Α`) reads as its Latin
    ///   letter only in a whitespace-delimited token that holds at least as many
    ///   Latin letters and digits as Cyrillic and Greek letters, so Cyrillic and
    ///   Greek prose keep their letters;
    /// * a Unicode space (NBSP, U+2007, U+202F, U+3000) reads as a space. When
    ///   one sits between two ASCII letters or digits, a second view drops it,
    ///   so `dia betes` reads `diabetes` there.
    ///
    /// The map is exact: a span maps back to every original byte from its first
    /// to its last character, the dropped ones inside it included. Nothing
    /// folds in ASCII text, so it has no view and reads exactly as before.
    pub(crate) fn folded_views(text: &str) -> Vec<Self> {
        Self::fold_views(text, false)
    }

    /// Whether [`NormalizedText::glyph_views`] can read `text` differently from
    /// [`NormalizedText::folded_views`]: only a full-width `＆`, `＃` or `％` reads
    /// another way there.
    pub(crate) fn may_glyph_fold(text: &str) -> bool {
        text.contains(['\u{FF06}', '\u{FF03}', '\u{FF05}'])
    }

    /// The folded views with the NORM-GLYPH escape rule: a look-alike or
    /// full-width `x`, a full-width `＃` and full-width hex digits open an escape
    /// as their ASCII forms do ([`opens_escape_glyph`]). The registry scans these
    /// as an **extra** set of views and unions their spans with those of
    /// [`NormalizedText::folded_views`], which stay exactly as they were: decoding
    /// more filler loses word boundaries and whole-token masks the old views
    /// give, so the new rule may only add masks, never replace the old views.
    pub(crate) fn glyph_views(text: &str) -> Vec<Self> {
        Self::fold_views(text, true)
    }

    fn fold_views(text: &str, glyph: bool) -> Vec<Self> {
        if text.is_ascii() {
            return Vec::new();
        }
        let items: Vec<(usize, char, Fold)> = text
            .char_indices()
            .map(|(at, ch)| (at, ch, fold(ch)))
            .collect();
        let glyphs = latin_tokens(&items);
        // Whether each item reads as an ASCII letter or digit, then the nearest
        // such answer on each side, invisible characters skipped.
        let alnum: Vec<bool> = items
            .iter()
            .zip(&glyphs)
            .map(|(&(_, _, fold), &latin)| match fold {
                Fold::Keep(ch) => ch.is_ascii_alphanumeric(),
                Fold::Glyph(_) => latin,
                _ => false,
            })
            .collect();
        let side = |order: &mut dyn Iterator<Item = usize>| {
            let mut seen = vec![false; items.len()];
            let mut last = false;
            for index in order {
                seen[index] = last;
                if items[index].2 != Fold::Drop {
                    last = alnum[index];
                }
            }
            seen
        };
        let before = side(&mut (0..items.len()));
        let after = side(&mut (0..items.len()).rev());
        let inside = |index: usize| before[index] && after[index];
        let joins = (0..items.len()).any(|i| items[i].2 == Fold::Space && inside(i));
        let mut views = Vec::new();
        for join in [false, true].into_iter().take(1 + usize::from(joins)) {
            let mut chars = Vec::with_capacity(items.len());
            let mut bounds: Vec<(usize, usize)> = Vec::with_capacity(items.len());
            let mut run: Option<(usize, usize)> = None;
            for (index, &(at, ch, fold)) in items.iter().enumerate() {
                let end = at + ch.len_utf8();
                let mapped = match fold {
                    Fold::Drop => None,
                    Fold::Space if join && inside(index) => None,
                    Fold::Space => Some(' '),
                    Fold::Punct(ascii)
                        if before[index]
                            || after[index]
                            || if glyph {
                                opens_escape_glyph(index, ascii, &items, &glyphs)
                            } else {
                                opens_escape(index, ascii, &items)
                            } =>
                    {
                        Some(ascii)
                    }
                    Fold::Glyph(latin) if glyphs[index] => Some(latin),
                    Fold::Keep(mapped) => Some(mapped),
                    Fold::Punct(_) | Fold::Glyph(_) => Some(ch),
                };
                let Some(mapped) = mapped else {
                    let (first, count) = run.unwrap_or((at, 0));
                    run = Some((first, count + 1));
                    if count + 1 > MAX_FOLDED_RUN {
                        // Over the cap: the run is one boundary, no longer dropped.
                        if count == MAX_FOLDED_RUN {
                            chars.push(RUN_BOUNDARY);
                            bounds.push((first, end));
                        }
                        bounds.last_mut().expect("boundary pushed").1 = end;
                    }
                    continue;
                };
                run = None;
                chars.push(mapped);
                bounds.push((at, end));
            }
            let folded: String = chars.iter().collect();
            if folded != text {
                let char_starts = folded.char_indices().map(|(at, _)| at).collect();
                views.push(Self {
                    text: Arc::new(folded),
                    char_starts,
                    orig_bounds: bounds.into(),
                    identity: false,
                    compact: false,
                });
            }
        }
        views
    }
}

/// Whether normalisation returns `text` unchanged: every character maps to
/// itself, none is dropped, no run folds, and the OCR fold does nothing.
fn is_identity(text: &str, ocr: bool) -> bool {
    if text.is_ascii() {
        if text
            .bytes()
            .any(|byte| matches!(byte, b'\n' | b'\r' | b'\t' | 0x0b | 0x0c))
        {
            return false;
        }
        return !ocr || !ocr_would_fold(text.as_bytes());
    }
    for ch in text.chars() {
        if is_line_break_or_tab(ch)
            || matches!(ch, '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{3002}')
            || normalize_char(ch) != Some(ch)
        {
            return false;
        }
    }
    !ocr || !ocr_would_fold(text.as_bytes())
}

/// The separator bytes of an ASCII text: space, tab and the ASCII line breaks.
fn is_ascii_separator(byte: u8) -> bool {
    byte == b' ' || is_ascii_break_or_tab(byte)
}

fn is_ascii_break_or_tab(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

/// Whether a quoted-printable soft break starts in `bytes`.
fn has_soft_break(bytes: &[u8]) -> bool {
    let mut at = 0;
    while let Some(found) = bytes[at..].iter().position(|&byte| byte == b'=') {
        let mut cursor = at + found + 1;
        while matches!(bytes.get(cursor), Some(b' ' | b'\t')) {
            cursor += 1;
        }
        if matches!(bytes.get(cursor), Some(b'\r' | b'\n')) {
            return true;
        }
        at += found + 1;
    }
    false
}

/// [`run_folds`] for one ASCII separator run.
fn ascii_run_folds(group: &[u8]) -> bool {
    let (mut breaks, mut previous) = (0usize, None);
    for &byte in group {
        // A tab is no line break here: it makes the run fold, but it does not
        // count toward the break cap (as `run_folds` counts them).
        if matches!(byte, b'\n' | b'\r' | 0x0b | 0x0c)
            && !(byte == b'\n' && previous == Some(b'\r'))
        {
            breaks += 1;
        }
        previous = Some(byte);
    }
    breaks <= MAX_FOLDED_BREAKS && group.len() <= MAX_FOLDED_RUN
}

/// Whether [`fold_ocr_confusables`] would rewrite a confusable in `bytes`.
fn ocr_would_fold(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .enumerate()
        .any(|(at, &byte)| matches!(byte, b'O' | b'o' | b'l' | b'I') && ocr_folds_at(bytes, at))
}

/// [`fold_ocr_confusables`] for one confusable at `at`.
fn ocr_folds_at(bytes: &[u8], at: usize) -> bool {
    let touches_digit = at
        .checked_sub(1)
        .is_some_and(|left| bytes[left].is_ascii_digit())
        || bytes.get(at + 1).is_some_and(u8::is_ascii_digit);
    touches_digit || (digit_across_bytes(bytes, at, false) && digit_across_bytes(bytes, at, true))
}

fn digit_across_bytes(bytes: &[u8], at: usize, forward: bool) -> bool {
    let mut cursor = at;
    loop {
        if forward {
            cursor += 1;
            if cursor >= bytes.len() {
                return false;
            }
        } else {
            if cursor == 0 {
                return false;
            }
            cursor -= 1;
        }
        let byte = bytes[cursor];
        if byte.is_ascii_digit() {
            return true;
        }
        if !run_material_byte(byte) {
            return false;
        }
    }
}

/// [`run_material`] over bytes.
fn run_material_byte(byte: u8) -> bool {
    byte.is_ascii_digit()
        || matches!(byte, b'O' | b'o' | b'l' | b'I')
        || matches!(byte, b' ' | b'-' | b'.' | b'/' | b'(' | b')')
}

#[derive(Clone, Copy, PartialEq)]
enum Fold {
    /// Invisible: dropped.
    Drop,
    /// A Unicode space.
    Space,
    /// Full-width punctuation: its ASCII form beside an ASCII letter or digit.
    Punct(char),
    /// A Cyrillic or Greek look-alike: its Latin letter in a Latin token.
    Glyph(char),
    /// Always read as this character.
    Keep(char),
}

fn fold(ch: char) -> Fold {
    if is_zero_width(ch) {
        return Fold::Drop;
    }
    if is_unicode_space(ch) {
        return Fold::Space;
    }
    if is_dash(ch) {
        return Fold::Keep('-');
    }
    if let Some(digit) = unicode_digit_value(ch) {
        return Fold::Keep(char::from(b'0' + digit as u8));
    }
    if matches!(ch as u32, 0xFF01..=0xFF5E | 0x2100..=0x214F | 0x1D400..=0x1D7FF) {
        let mut compat = std::iter::once(ch).nfkc();
        if let (Some(ascii), None) = (compat.next(), compat.next()) {
            if ascii.is_ascii_alphanumeric() {
                return Fold::Keep(ascii);
            }
            if ascii.is_ascii_graphic() {
                return Fold::Punct(ascii);
            }
        }
    }
    if is_cyrillic(ch) || is_greek(ch) {
        let mut lower = ch.to_lowercase();
        let single = lower.next().filter(|_| lower.next().is_none());
        if let Some(latin) = homoglyph(ch).or_else(|| single.and_then(homoglyph)) {
            let upper = ch.is_uppercase();
            return Fold::Glyph(if upper {
                latin.to_ascii_uppercase()
            } else {
                latin
            });
        }
    }
    Fold::Keep(ch)
}

/// Whether the full-width character at `index`, which reads as `ascii`, opens
/// an escape there — wherever it sits, and whether or not an ASCII letter or
/// digit stands beside it (NORM-2 r1).
///
/// `＆#100;`, `＆#x41;` and `＆nbsp;` each begin an entity, `％41` a percent
/// escape. An escape that opens a value has a blank and a `#` beside it, never
/// the letter or digit the neighbour rule needs, so without this rule the escape
/// it begins is never decoded and the value stays in clear. A `＆` or `％` that
/// opens nothing is ordinary punctuation and stays: no Chinese sentence has
/// `＆#`, so the fold never reaches prose.
fn opens_escape(index: usize, ascii: char, items: &[(usize, char, Fold)]) -> bool {
    // The characters that follow, invisible ones skipped: they drop out of the
    // view, so none of them stands between a fold and the escape it opens.
    let mut after = items[index + 1..]
        .iter()
        .filter(|(_, _, fold)| *fold != Fold::Drop)
        .map(|&(_, ch, _)| ch);
    match ascii {
        // `&#100;` and `&#x41;`: a numeric reference, its `;` optional.
        '&' => match after.next() {
            Some('#') => after.next().is_some_and(|ch| ch.is_ascii_hexdigit()),
            // `&nbsp;`: a named reference reads to its `;`.
            Some(ch) if ch.is_ascii_alphabetic() => {
                let mut name = 1;
                while name < decode::MAX_ENTITY_BODY
                    && after.next().is_some_and(|ch| ch.is_ascii_alphanumeric())
                {
                    name += 1;
                }
                after.next() == Some(';')
            }
            _ => false,
        },
        // `％41`: a percent escape is two hex digits.
        '%' => {
            after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
                && after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
        }
        _ => false,
    }
}

/// [`opens_escape`] for the glyph views only (NORM-GLYPH): the escape is read as the folded view reads it ([`escape_read`]), so a
/// look-alike `x` (`＆#х73;`) or a look-alike hex digit opens it like the ASCII
/// one, and the full-width `＃` of `＆＃73;` folds with it.
fn opens_escape_glyph(
    index: usize,
    ascii: char,
    items: &[(usize, char, Fold)],
    latin: &[bool],
) -> bool {
    // The characters that follow, invisible ones skipped: they drop out of the
    // view, so none of them stands between a fold and the escape it opens.
    let mut after = items[index + 1..]
        .iter()
        .enumerate()
        .map(|(at, _)| index + 1 + at)
        .filter(|&at| items[at].2 != Fold::Drop)
        .map(|at| escape_read(at, items, latin));
    match ascii {
        // `&#100;`, `&#x41;` and `&#X41;`: a numeric reference, its `;` optional.
        // The body is one hex digit (decimal) or an `x` and one hex digit, read
        // off the same iterator so the `x` is not consumed twice.
        '&' => match after.next() {
            Some('#') => {
                let body = after.by_ref();
                let first = body.next();
                first.is_some_and(|ch| ch.is_ascii_hexdigit())
                    || matches!(first, Some('x' | 'X')
                        if body.next().is_some_and(|ch| ch.is_ascii_hexdigit()))
            }
            // `&nbsp;`: a named reference reads to its `;`.
            Some(ch) if ch.is_ascii_alphabetic() => {
                let mut name = 1;
                while name < decode::MAX_ENTITY_BODY
                    && after.next().is_some_and(|ch| ch.is_ascii_alphanumeric())
                {
                    name += 1;
                }
                after.next() == Some(';')
            }
            _ => false,
        },
        // `％41`: a percent escape is two hex digits.
        '%' => {
            after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
                && after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
        }
        // `＆＃100;`: the `#` of a reference is full-width too, and folds once
        // the ampersand before it has been shown to open the escape.
        '#' => {
            opens_reference(index, items, latin)
                && after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
        }
        _ => false,
    }
}

/// How the character at `index` reads inside an escape: a full-width
/// punctuation as its ASCII form, a look-alike as its Latin letter where the
/// view folds it (a Latin token, the rule the glyph fold itself reads), and a
/// mapped character as what it maps to. Anything else reads as itself.
///
/// A `Fold::Drop` never reaches here: the callers skip those, exactly as they do
/// for the invisible characters between the two halves of an escape.
fn escape_read(index: usize, items: &[(usize, char, Fold)], latin: &[bool]) -> char {
    match items[index].2 {
        Fold::Glyph(letter) if latin[index] => letter,
        Fold::Keep(mapped) => mapped,
        Fold::Punct(mapped) => mapped,
        _ => items[index].1,
    }
}

/// Whether the character before `index`, invisible ones skipped, reads as the
/// ampersand of a reference. One backward step per caller, so the whole scan
/// stays linear.
fn opens_reference(index: usize, items: &[(usize, char, Fold)], latin: &[bool]) -> bool {
    items[..index]
        .iter()
        .rposition(|&(_, _, fold)| fold != Fold::Drop)
        .is_some_and(|at| escape_read(at, items, latin) == '&')
}

/// Per item, whether its whitespace-delimited token is Latin: it holds a Latin
/// letter or ASCII digit, and at least as many of them as Cyrillic and Greek
/// letters (look-alikes included). One pass per token: linear.
fn latin_tokens(items: &[(usize, char, Fold)]) -> Vec<bool> {
    let mut latin = vec![false; items.len()];
    let mut start = 0;
    let (mut ours, mut theirs) = (0usize, 0usize);
    for index in 0..=items.len() {
        let read = items.get(index).map(|&(_, ch, fold)| match fold {
            Fold::Space => ' ',
            Fold::Keep(mapped) => mapped,
            _ => ch,
        });
        match read {
            Some(ch) if !ch.is_whitespace() => {
                if ch.is_ascii_alphanumeric() || matches!(ch, '\u{C0}'..='\u{24F}') {
                    ours += 1;
                } else if is_cyrillic(ch) || is_greek(ch) {
                    theirs += 1;
                }
            }
            _ => {
                let is_latin = ours > 0 && ours >= theirs;
                latin[start..index].iter_mut().for_each(|at| *at = is_latin);
                start = index + 1;
                (ours, theirs) = (0, 0);
            }
        }
    }
    latin
}

/// Map one original char, or `None` when it is stripped.
fn normalize_char(ch: char) -> Option<char> {
    if is_zero_width(ch) {
        return None;
    }
    if let Some(digit) = unicode_digit_value(ch) {
        return Some((b'0' + digit as u8) as char);
    }
    if is_unicode_space(ch) {
        return Some(' ');
    }
    if is_dash(ch) {
        return Some('-');
    }
    if let Some(ascii) = fullwidth_ascii(ch) {
        return Some(ascii);
    }
    Some(ch)
}

/// Fold the fullwidth ASCII block U+FF01–U+FF5E to ASCII `!`–`~`.
///
/// This covers the fullwidth letters, the commercial `＠`, and the fullwidth
/// punctuation this layer used to leak (`．` U+FF0E, `＋` U+FF0B, `－` U+FF0D,
/// `／` U+FF0F, `：` U+FF1A, `（`/`）` U+FF08/U+FF09). Fullwidth digits are
/// already handled by [`unicode_digit_value`], which runs first.
fn fullwidth_ascii(ch: char) -> Option<char> {
    let code = ch as u32;
    if (0xFF01..=0xFF5E).contains(&code) {
        Some((b'!' as u32 + (code - 0xFF01)) as u8 as char)
    } else {
        None
    }
}

/// Fold the ideographic full stop `。` (U+3002) to `.` only when it sits
/// between two digits.
///
/// A CJK sentence often ends `…。`, and a bare number followed by that mark
/// must not gain a date separator; when the mark is genuinely a thousands
/// separator inside a number it is folded (P2).
fn fold_ideographic_stop(chars: &mut [char]) {
    let count = chars.len();
    for index in 1..count.saturating_sub(1) {
        if chars[index] == '\u{3002}'
            && chars[index - 1].is_ascii_digit()
            && chars[index + 1].is_ascii_digit()
        {
            chars[index] = '.';
        }
    }
}

/// Zero-width and otherwise invisible characters, stripped before scanning.
/// The set lives once, in [`crate::contacts::fold::is_default_ignorable`].
fn is_zero_width(ch: char) -> bool {
    crate::contacts::fold::is_default_ignorable(ch)
}

/// Unicode space separators folded to ASCII space.
pub(crate) fn is_unicode_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

/// Dashes folded to ASCII `-`.
fn is_dash(ch: char) -> bool {
    matches!(ch, '\u{2010}'..='\u{2015}' | '\u{2212}')
}

/// Line breaks: the ASCII newlines, the vertical tab, form feed, NEL and the
/// Unicode line and paragraph separators.
fn is_line_break(ch: char) -> bool {
    matches!(
        ch,
        '\n' | '\u{000B}' | '\u{000C}' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}'
    )
}

/// Line breaks and tabs. Inside an identifier they are separators, not content.
fn is_line_break_or_tab(ch: char) -> bool {
    ch == '\t' || is_line_break(ch)
}

/// Whether `text` holds a line break: `\n`, `\r`, the vertical tab, the form
/// feed, NEL or a Unicode line or paragraph separator. Shared with the
/// National Insurance recogniser, whose suffix letter may not cross one
/// (NINO-NEWLINE-SUFFIX); a tab is no line break and still folds.
pub(crate) fn holds_line_break(text: &str) -> bool {
    text.chars().any(is_line_break)
}

/// Whether a separator run folds to one space: at most
/// [`MAX_FOLDED_BREAKS`] line breaks (a CRLF counts once) and at most
/// [`MAX_FOLDED_RUN`] separator characters in all. Zero-width characters count
/// too, so an invisible run cannot stretch a masked region either.
fn run_folds(group: &[(usize, char)]) -> bool {
    let mut breaks = 0;
    let mut previous = None;
    for &(_, ch) in group {
        if is_line_break(ch) && !(ch == '\n' && previous == Some('\r')) {
            breaks += 1;
        }
        previous = Some(ch);
    }
    breaks <= MAX_FOLDED_BREAKS && group.len() <= MAX_FOLDED_RUN
}

/// Characters that can sit inside a run of separators: spaces, line breaks,
/// tabs and zero-width characters.
fn is_separator_run(ch: char) -> bool {
    ch == ' ' || is_line_break_or_tab(ch) || is_unicode_space(ch) || is_zero_width(ch)
}

/// Length of the run of separator characters at the start of `source` (0 when
/// its first character is not one).
fn separator_run_len(source: &[(usize, char)]) -> usize {
    source
        .iter()
        .take_while(|&&(_, ch)| is_separator_run(ch))
        .count()
}

/// The chars of `text` with every quoted-printable soft break removed, each kept
/// char paired with its original byte offset.
///
/// A soft break is what a mail client writes when it wraps a long line. Removing
/// it before the folds means the two sides join with nothing between them, so
/// `name=\r\n@example.invalid` scans as `name@example.invalid`. The removed bytes
/// still lie inside the offsets of the chars on either side, so a span that
/// straddles the wrap covers them.
fn without_soft_breaks(text: &str) -> Vec<(usize, char)> {
    // No `=` means no soft break: one pass, one buffer.
    if !text.contains('=') {
        return text.char_indices().collect();
    }
    let all: Vec<(usize, char)> = text.char_indices().collect();
    let mut kept = Vec::with_capacity(all.len());
    let mut index = 0;
    while index < all.len() {
        let skipped = soft_break_len(&all[index..]);
        if skipped > 0 {
            index += skipped;
        } else {
            kept.push(all[index]);
            index += 1;
        }
    }
    kept
}

/// The number of chars of the soft break at the start of `source`, or 0 when no
/// soft break starts there. The break is an `=`, any blanks (spaces, tabs and
/// the other blanks [`is_separator_run`] takes), then `\r\n`, `\r` or `\n`. A
/// plain `=` (`id=123`, `x = 1`, a trailing `=`) is not one.
fn soft_break_len(source: &[(usize, char)]) -> usize {
    if source.first().map(|&(_, ch)| ch) != Some('=') {
        return 0;
    }
    let blanks = source[1..]
        .iter()
        .take_while(|&&(_, ch)| is_separator_run(ch) && !is_line_break(ch))
        .count();
    let line_break = match source.get(1 + blanks).map(|&(_, ch)| ch) {
        Some('\r') if source.get(2 + blanks).map(|&(_, ch)| ch) == Some('\n') => 2,
        Some('\r' | '\n') => 1,
        _ => return 0,
    };
    1 + blanks + line_break
}

/// Zero code points of the Unicode decimal-digit blocks, so every `Nd`
/// character maps to its value. The list is the Unicode `Nd` block starts.
const DIGIT_ZEROS: &[u32] = &[
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6,
    0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80,
    0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0,
    0xFF10, 0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0,
    0x11650, 0x116C0, 0x11730, 0x118E0, 0x11C50, 0x11D50, 0x11DA0, 0x16A60, 0x16B50, 0x1D7CE,
    0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E950, 0x1FBF0,
];

/// The numeric value of any Unicode decimal digit, ASCII included.
pub(crate) fn unicode_digit_value(ch: char) -> Option<u32> {
    let code = ch as u32;
    DIGIT_ZEROS
        .iter()
        .find(|zero| code >= **zero && code < **zero + 10)
        .map(|zero| code - *zero)
}

/// Whether a char can sit inside a digit-ish OCR run.
fn run_material(ch: char) -> bool {
    ch.is_ascii_digit() || is_confusable(ch) || is_number_separator(ch)
}

/// The separators a printed number may use between digit groups.
fn is_number_separator(ch: char) -> bool {
    matches!(ch, ' ' | '-' | '.' | '/' | '(' | ')')
}

/// The OCR confusables the fold rewrites.
fn is_confusable(ch: char) -> bool {
    matches!(ch, 'O' | 'o' | 'l' | 'I')
}

/// Fold `O`/`o` → `0` and `l`/`I` → `1`, but only a single confusable that sits
/// between two digit groups or touches a digit directly (P3-4).
///
/// A whole letter word is never rewritten: `Ilo` after a number, `om` and
/// `IBAN-ra` stay intact because no confusable in them has a digit on both
/// sides (across separators) or immediately beside it. The leading confusable
/// of `O6 l2` is folded because it touches the `6` directly.
fn fold_ocr_confusables(chars: &mut [char]) {
    let count = chars.len();
    let mut index = 0;
    while index < count {
        if is_confusable(chars[index]) {
            let touches_digit = index
                .checked_sub(1)
                .and_then(|left| chars.get(left))
                .is_some_and(|ch| ch.is_ascii_digit())
                || chars.get(index + 1).is_some_and(|ch| ch.is_ascii_digit());
            let between_digits =
                digit_across(chars, index, false) && digit_across(chars, index, true);
            if touches_digit || between_digits {
                chars[index] = match chars[index] {
                    'O' | 'o' => '0',
                    'l' | 'I' => '1',
                    other => other,
                };
            }
        }
        index += 1;
    }
}

/// Whether a digit lies across from `index` once separators and other
/// confusables are skipped; any other character stops the scan, so the fold
/// cannot reach into a following word.
fn digit_across(chars: &[char], index: usize, forward: bool) -> bool {
    let count = chars.len();
    let mut cursor = index;
    loop {
        if forward {
            cursor += 1;
            if cursor >= count {
                return false;
            }
        } else {
            if cursor == 0 {
                return false;
            }
            cursor -= 1;
        }
        let ch = chars[cursor];
        if ch.is_ascii_digit() {
            return true;
        }
        if !run_material(ch) {
            return false;
        }
    }
}

/// Maximal runs of ASCII digits plus the separators a printed number may use.
///
/// A separator is kept only when the next char is a digit, so trailing
/// punctuation stays outside the span.
pub fn numeric_runs(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut runs = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        let mut cursor = index;
        let mut last_digit_end = index;
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            if byte.is_ascii_digit() {
                last_digit_end = cursor + 1;
                cursor += 1;
            } else if matches!(byte, b' ' | b'-' | b'.' | b'/')
                && cursor + 1 < bytes.len()
                && bytes[cursor + 1].is_ascii_digit()
            {
                cursor += 1;
            } else {
                break;
            }
        }
        runs.push((start, last_digit_end));
        index = cursor.max(index + 1);
    }
    runs
}

/// Consume up to `max_alnum` ASCII alphanumerics starting at `start`, allowing
/// a single separator (` `, `-`, `.`, `/`) between them. Returns the end offset
/// (one past the last consumed alphanumeric).
pub fn consume_alnum(text: &str, start: usize, max_alnum: usize) -> usize {
    let bytes = text.as_bytes();
    let mut cursor = start;
    let mut consumed = 0usize;
    let mut previous_separator = false;
    while cursor < bytes.len() && consumed < max_alnum {
        let byte = bytes[cursor];
        if byte.is_ascii_alphanumeric() {
            consumed += 1;
            previous_separator = false;
            cursor += 1;
        } else if matches!(byte, b' ' | b'-' | b'.' | b'/') && !previous_separator {
            let next_is_alnum =
                cursor + 1 < bytes.len() && bytes[cursor + 1].is_ascii_alphanumeric();
            if !next_is_alnum {
                break;
            }
            previous_separator = true;
            cursor += 1;
        } else {
            break;
        }
    }
    cursor
}

/// The ASCII digits of a raw run, discarding separators.
pub fn ascii_digits(raw: &str) -> String {
    raw.chars().filter(|ch| ch.is_ascii_digit()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::Strategy as _;

    /// K-REGISTRY-PERF: inside a scan a view of its text is the view a fresh
    /// build returns, another text is built on its own, and the scan's end
    /// forgets the text.
    #[test]
    fn a_shared_view_is_the_view_a_fresh_build_returns() {
        let text = "Ｏ6 l2\u{200B}34 ＋33\r\n6 12 FR76\n3000 jean＠example．com";
        let fresh = [false, true].map(|ocr| NormalizedText::new(text, ocr));
        let views = SharedViews::new(text);
        for (ocr, fresh) in [false, true].into_iter().zip(&fresh) {
            let shared = NormalizedText::new(text, ocr);
            assert_eq!(shared.text, fresh.text);
            assert_eq!(shared.char_starts, fresh.char_starts);
            assert_eq!(shared.orig_bounds, fresh.orig_bounds);
            assert!(Arc::ptr_eq(
                &shared.text,
                &NormalizedText::new(text, ocr).text
            ));
        }
        assert_eq!(NormalizedText::new("O6 l2", true).text(), "06 12");
        drop(views);
        assert!(SHARED.with(|shared| shared.borrow().depth == 0));
    }

    fn assert_matches_slow(text: &str, ocr: bool) {
        let fast = NormalizedText::build(text, ocr);
        let slow = NormalizedText::build_slow(text, ocr);
        assert_eq!(fast.text(), slow.text(), "{text:?} ocr={ocr}");
        for start in 0..=text.len() {
            for end in start..=text.len() {
                assert_eq!(
                    fast.to_original(start, end),
                    slow.to_original(start, end),
                    "{text:?} ocr={ocr} {start}..{end}",
                );
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        #[test]
        fn the_identity_path_matches_the_slow_build_on_ascii(
            bytes in proptest::collection::vec(0x00u8..=0x7f, 0..80),
            ocr in proptest::prelude::any::<bool>(),
        ) {
            let text: String = bytes.into_iter().map(char::from).collect();
            assert_matches_slow(&text, ocr);
        }

        #[test]
        fn the_identity_path_matches_the_slow_build_on_mixed_text(
            chars in proptest::collection::vec(
                proptest::prop_oneof![
                    (0x00u8..=0x7f).prop_map(char::from),
                    proptest::sample::select(vec![
                        'é', '\u{301}', '\u{200B}', '\u{FF11}', '\u{A0}', '。', '中', '𝐀',
                        '\u{2028}', '\u{85}',
                    ]),
                ],
                0..60,
            ),
            ocr in proptest::prelude::any::<bool>(),
        ) {
            let text: String = chars.into_iter().collect();
            assert_matches_slow(&text, ocr);
        }
    }

    fn folded(text: &str) -> Vec<String> {
        let views = NormalizedText::folded_views(text);
        views.iter().map(|view| view.text().to_string()).collect()
    }

    /// NORM-1: what the folded views read, and what they leave alone.
    #[test]
    fn folded_views_read_look_alikes_and_leave_prose_alone() {
        assert!(folded("plain ASCII: a@b.c 4111 1111").is_empty());
        assert!(folded("Привет, как дела? 今天，好！ Ελλάδα").is_empty());
        assert_eq!(folded("ali\u{200B}ce@gmail.c\u{43E}m"), ["alice@gmail.com"]);
        assert_eq!(folded("𝐀𝐊𝐈𝐀 𝟒𝟐 ℎ ＭＲＮ："), ["AKIA 42 h MRN:"]);
        assert_eq!(folded("\u{455}k-pr\u{43E}j AKI\u{410}"), ["sk-proj AKIA"]);
        // Punctuation folds beside ASCII only; a Cyrillic word keeps its letters.
        assert_eq!(folded("注意：１２ 你好：好"), ["注意:12 你好：好"]);
        assert_eq!(folded("сом com\u{3000}"), ["сом com "]);
        // A space inside an ASCII word: a spaced view, then a joined one.
        assert_eq!(
            folded("dia\u{A0}betes 06\u{202F}12"),
            ["dia betes 06 12", "diabetes 0612"]
        );
    }

    /// NORM-2 r1: a full-width `＆` or `％` folds wherever it sits when it
    /// opens an escape, and stays ordinary punctuation when it does not.
    #[test]
    fn a_full_width_escape_character_folds_wherever_it_sits() {
        // At the start of a token, beside a blank and a `#`.
        assert_eq!(
            folded("I have \u{ff06}#100;iabetes"),
            ["I have &#100;iabetes"]
        );
        assert_eq!(folded("x\u{ff06}#x41;"), ["x&#x41;"]);
        // A named escape and a percent escape fold the same way.
        assert_eq!(folded("mail \u{ff06}nbsp;x"), ["mail &nbsp;x"]);
        assert_eq!(folded("x.invalid/\u{ff05}41x"), ["x.invalid/%41x"]);
        // An invisible character between the `＆` and its body drops out of the
        // view, so it does not stand in the way of the escape.
        assert_eq!(folded("x\u{ff06}\u{200B}#41;y"), ["x&#41;y"]);
        // Ordinary punctuation: nothing to fold, so no view at all.
        assert!(folded("\u{ff06}\u{ff05}\u{ff06}\u{ff05}").is_empty());
        assert!(folded("\u{ff06} note \u{ff05} of it").is_empty());
        assert!(folded("价％和＆人").is_empty());
        // Chinese prose keeps both, whatever stands beside them.
        for text in [
            "预算增加１５％，库存＆物流都正常。",
            "他说：“明天见！”然后就走了，＆其它人无关。",
        ] {
            let views = folded(text);
            assert!(
                views.iter().all(|view| view.contains('＆')),
                "{text:?} -> {views:?}"
            );
        }
        // Beside no ASCII letter or digit and opening no escape, a `％` stays
        // too: the neighbour rule alone would not have touched it either.
        assert!(folded("预算增加％，库存正常。").is_empty());
    }

    #[test]
    fn a_folded_span_maps_back_to_every_original_byte() {
        let text = "x \u{415}S91\u{200B}2100\u{AD}\u{A0}0418 y";
        for view in NormalizedText::folded_views(text) {
            let start = view.text().find("ES91").expect("folded value");
            let end = view.text().find(" y").expect("end");
            let (from, to) = view.to_original(start, end).expect("maps back");
            assert_eq!(&text[from..to], "\u{415}S91\u{200B}2100\u{AD}\u{A0}0418");
        }
    }

    #[test]
    fn an_invisible_run_over_the_cap_is_a_boundary_in_the_folded_view() {
        let within = format!("FR76{}3000\u{43E}", "\u{200B}".repeat(8));
        assert_eq!(folded(&within), ["FR763000o"]);
        let over = format!("FR76{}3000", "\u{200B}".repeat(30));
        let views = NormalizedText::folded_views(&over);
        assert_eq!(views[0].text(), "FR76\u{0}3000");
        assert_eq!(views[0].to_original(4, 5), Some((4, over.len() - 4)));
    }

    #[test]
    fn unicode_digits_map_to_ascii() {
        assert_eq!(unicode_digit_value('7'), Some(7));
        assert_eq!(unicode_digit_value('７'), Some(7));
        assert_eq!(unicode_digit_value('٤'), Some(4));
        assert_eq!(unicode_digit_value('a'), None);
        assert_eq!(unicode_digit_value('Ⅷ'), None);
    }

    #[test]
    fn separators_fold_and_zero_width_is_stripped() {
        let normalized =
            NormalizedText::new("06\u{00A0}12\u{202F}34\u{2010}56\u{2212}78\u{200B}9", true);
        assert_eq!(normalized.text(), "06 12 34-56-789");
    }

    #[test]
    fn fullwidth_digits_are_digits() {
        let normalized = NormalizedText::new("０６ １２ ３４ ５６ ７８", true);
        assert_eq!(normalized.text(), "06 12 34 56 78");
    }

    #[test]
    fn offset_map_returns_original_bytes() {
        let text = "tél : ０６\u{00A0}１２ ３４ ５６ ７８!";
        let normalized = NormalizedText::new(text, true);
        let start = normalized.text().find("06").expect("normalised digits");
        let end = start + "06 12 34 56 78".len();
        let (orig_start, orig_end) = normalized.to_original(start, end).expect("maps back");
        assert_eq!(
            &text[orig_start..orig_end],
            "０６\u{00A0}１２ ３４ ５６ ７８"
        );
    }

    #[test]
    fn fullwidth_letters_and_at_fold() {
        let normalized = NormalizedText::new("ａｐｐ １０.０.０.５", false);
        assert_eq!(normalized.text(), "app 10.0.0.5");
        let mail = NormalizedText::new("ｊｅａｎ＠ｅｘａｍｐｌｅ.ｃｏｍ", false);
        assert_eq!(mail.text(), "jean@example.com");
    }

    #[test]
    fn fullwidth_punctuation_folds_to_ascii() {
        let ip = NormalizedText::new("１９２．１６８．０．１", false);
        assert_eq!(ip.text(), "192.168.0.1");
        let mail = NormalizedText::new("jean＠example．com", false);
        assert_eq!(mail.text(), "jean@example.com");
        let extras = NormalizedText::new("＋－／：（），；", false);
        assert_eq!(extras.text(), "+-/:(),;");
    }

    #[test]
    fn ideographic_stop_folds_only_between_digits() {
        assert_eq!(
            NormalizedText::new("192。168。0。1", false).text(),
            "192.168.0.1"
        );
        // A sentence-ending stop is untouched, so it never becomes a date dot.
        assert_eq!(
            NormalizedText::new("le total 42。", false).text(),
            "le total 42。"
        );
        assert_eq!(NormalizedText::new("。42。", false).text(), "。42。");
    }

    #[test]
    fn ocr_fold_only_touches_confusables_beside_digits() {
        let normalized = NormalizedText::new("+33 l 99 OO 41 27", true);
        assert_eq!(normalized.text(), "+33 1 99 00 41 27");
        let leading = NormalizedText::new("O6 l2", true);
        assert_eq!(leading.text(), "06 12");
        let words = NormalizedText::new("I Owe Owen an O", true);
        assert_eq!(words.text(), "I Owe Owen an O");
        // A whole letter word next to a number is not folded (P3-4).
        let after = NormalizedText::new("123456 Ilo om IBAN-ra", true);
        assert_eq!(after.text(), "123456 Ilo om IBAN-ra");
    }

    #[test]
    fn numeric_runs_keep_grouping_and_trim_punctuation() {
        assert_eq!(numeric_runs("x 06 12 34 56 78."), vec![(2, 16)]);
        assert_eq!(ascii_digits("06 12 34 56 78"), "0612345678");
    }

    #[test]
    fn a_line_break_or_tab_folds_its_run_to_one_separator() {
        assert_eq!(NormalizedText::new("FR76\n3000", false).text(), "FR76 3000");
        assert_eq!(
            NormalizedText::new("FR76\r\n3000", false).text(),
            "FR76 3000"
        );
        assert_eq!(NormalizedText::new("FR76\r3000", false).text(), "FR76 3000");
        assert_eq!(NormalizedText::new("FR76\t3000", false).text(), "FR76 3000");
        // Spaces around the break belong to the same separator.
        assert_eq!(
            NormalizedText::new("FR76 \r\n   3000", false).text(),
            "FR76 3000"
        );
        // Plain spaces keep their behaviour: no break, no fold.
        assert_eq!(
            NormalizedText::new("FR76  3000", false).text(),
            "FR76  3000"
        );
    }

    #[test]
    fn a_folded_break_maps_back_to_its_original_bytes() {
        let text = "x FR76 3000\r\n  0112 y";
        let normalized = NormalizedText::new(text, false);
        let start = normalized.text().find("FR76").expect("normalised value");
        let end = start + "FR76 3000 0112".len();
        let (orig_start, orig_end) = normalized.to_original(start, end).expect("maps back");
        assert_eq!(&text[orig_start..orig_end], "FR76 3000\r\n  0112");
    }

    #[test]
    fn a_wrapped_iban_is_still_found() {
        use crate::recognizer::Recognizer;
        use crate::recognizers::iban::IbanRecognizer;

        // FAKE: the checksum-valid specimen FR IBAN used across the tests.
        let text = "voici FR76 3000 6000 0112 3456\n7890 189 merci";
        let spans = IbanRecognizer::new().analyze(text);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(
            &text[spans[0].start..spans[0].end],
            "FR76 3000 6000 0112 3456\n7890 189"
        );
    }

    #[test]
    fn an_iban_broken_with_crlf_and_spaces_is_still_found() {
        use crate::recognizer::Recognizer;
        use crate::recognizers::iban::IbanRecognizer;

        // FAKE: the same specimen, broken with CRLF plus indentation.
        let text = "FR76 3000 6000 0112\r\n   3456 7890 189";
        let spans = IbanRecognizer::new().analyze(text);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(&text[spans[0].start..spans[0].end], text);
    }

    #[test]
    fn a_quoted_printable_soft_break_joins_the_value_it_wraps() {
        // FAKE: a mail client wrapped a quoted-printable line after the `=`.
        let text = "184030099900=\r\n123";
        let normalized = NormalizedText::new(text, false);
        assert_eq!(normalized.text(), "184030099900123");
        assert_eq!(
            normalized.to_original(0, normalized.text().len()),
            Some((0, text.len()))
        );
    }

    #[test]
    fn a_soft_break_joins_its_sides_with_nothing_between() {
        // FAKE: quoted-printable wraps with LF, CR, CRLF, and blanks before the break.
        for (text, joined) in [
            ("name=\r\n@example.invalid", "name@example.invalid"),
            ("name=\n@example.invalid", "name@example.invalid"),
            ("name=\r@example.invalid", "name@example.invalid"),
            ("na=\r\nme@example.invalid", "name@example.invalid"),
            ("name=  \r\n@example.invalid", "name@example.invalid"),
            ("name=\t\n@example.invalid", "name@example.invalid"),
            ("+33 6 12 3=\r\n4 56 78", "+33 6 12 34 56 78"),
            (
                "FR76 3000 6000 0112 3456 7890 1=\r\n89",
                "FR76 3000 6000 0112 3456 7890 189",
            ),
            ("a=\r\n=\r\nb", "ab"),
        ] {
            assert_eq!(NormalizedText::new(text, false).text(), joined, "{text:?}");
        }
    }

    #[test]
    fn a_plain_equals_sign_is_not_a_soft_break() {
        assert_eq!(NormalizedText::new("a=b", false).text(), "a=b");
        assert_eq!(NormalizedText::new("x = 1", false).text(), "x = 1");
        assert_eq!(NormalizedText::new("id=123", false).text(), "id=123");
        // Nothing or only blanks after the `=`: no break, so nothing is removed.
        assert_eq!(NormalizedText::new("name=", false).text(), "name=");
        assert_eq!(NormalizedText::new("name=  ", false).text(), "name=  ");
        assert_eq!(NormalizedText::new("a= b", false).text(), "a= b");
    }

    #[test]
    fn a_soft_break_maps_back_inside_a_span_that_straddles_it() {
        let text = "mail name=  \r\n@example.invalid, fin";
        let normalized = NormalizedText::new(text, false);
        let start = normalized.text().find("name").expect("local part");
        let end = start + "name@example.invalid".len();
        let (orig_start, orig_end) = normalized.to_original(start, end).expect("maps back");
        assert_eq!(&text[orig_start..orig_end], "name=  \r\n@example.invalid");
    }

    #[test]
    fn soft_break_edges_keep_char_boundaries() {
        // Still-encoded and decoded UTF-8 with the break inside the sequence, and
        // a break or `=` at the very end of the text.
        for (text, normalized) in [
            ("caf=C3=\r\n=A9 ok", "caf=C3=A9 ok"),
            ("café=\r\n@example.invalid", "café@example.invalid"),
            ("é=\r\né=\n", "éé"),
            ("=\r", ""),
            ("=\r\n", ""),
            ("=", "="),
            ("=  ", "=  "),
        ] {
            let view = NormalizedText::new(text, true);
            assert_eq!(view.text(), normalized, "{text:?}");
            if !normalized.is_empty() {
                let (start, end) = view.to_original(0, normalized.len()).expect("maps back");
                assert!(text.is_char_boundary(start) && text.is_char_boundary(end));
            }
        }
    }

    #[test]
    fn a_wrapped_phone_is_still_found() {
        use crate::recognizer::Recognizer;
        use crate::recognizers::phone::PhoneRecognizer;

        // FAKE: a number in the 555 fiction range, wrapped after the area code.
        let text = "appelle +1 (202)\r\n555-0142 demain";
        let spans = PhoneRecognizer::new().analyze(text);
        assert_eq!(spans.len(), 1, "{spans:?}");
        let found = &text[spans[0].start..spans[0].end];
        assert!(
            found.contains("\r\n") && found.ends_with("0142"),
            "{found:?}"
        );
    }

    #[test]
    fn a_run_within_the_caps_folds_to_one_space() {
        // Two line breaks and six spaces: eight separator characters.
        assert_eq!(
            NormalizedText::new("FR76\n\n      3000", false).text(),
            "FR76 3000"
        );
        // A CRLF is one line break, so two CRLFs are two breaks.
        assert_eq!(
            NormalizedText::new("FR76\r\n\r\n3000", false).text(),
            "FR76 3000"
        );
    }

    #[test]
    fn a_run_over_the_caps_is_a_hard_boundary() {
        // Three line breaks: a blank paragraph, not a wrap.
        assert_eq!(
            NormalizedText::new("FR76\n\n\n3000", false).text(),
            "FR76\u{0}3000"
        );
        assert_eq!(
            NormalizedText::new("FR76\r\n\r\n\r\n3000", false).text(),
            "FR76\u{0}3000"
        );
        // Two breaks but nine separator characters: over the eight cap.
        assert_eq!(
            NormalizedText::new("FR76\n\n       3000", false).text(),
            "FR76\u{0}3000"
        );
        // Zero-width characters count toward the cap as well.
        let invisible = format!("FR76\n{}3000", "\u{200B}".repeat(8));
        assert_eq!(
            NormalizedText::new(&invisible, false).text(),
            "FR76\u{0}3000"
        );
    }

    #[test]
    fn a_boundary_keeps_the_offset_map_exact() {
        let text = "FR76\n\n\n3000";
        let normalized = NormalizedText::new(text, false);
        let start = normalized.text().find("FR76").expect("left part");
        let (orig_start, orig_end) = normalized.to_original(start, start + 4).expect("maps back");
        assert_eq!(&text[orig_start..orig_end], "FR76");
        let tail = normalized.text().find("3000").expect("right part");
        let (orig_start, orig_end) = normalized.to_original(tail, tail + 4).expect("maps back");
        assert_eq!(&text[orig_start..orig_end], "3000");
    }

    #[test]
    fn a_zero_width_run_over_the_cap_is_a_hard_boundary() {
        // Nine invisible characters and no line break: over the eight cap.
        let invisible = format!("FR76{}3000", "\u{200B}".repeat(9));
        assert_eq!(
            NormalizedText::new(&invisible, false).text(),
            "FR76\u{0}3000"
        );
        // Eight stay within the cap and strip as before.
        let within = format!("FR76{}3000", "\u{200B}".repeat(8));
        assert_eq!(NormalizedText::new(&within, false).text(), "FR763000");
        // Spaces and invisible characters count together.
        let mixed = format!("FR76 {}3000", "\u{200B}".repeat(8));
        assert_eq!(NormalizedText::new(&mixed, false).text(), "FR76\u{0}3000");
    }

    #[test]
    fn an_iban_split_by_an_invisible_run_over_the_cap_does_not_merge() {
        use crate::recognizer::Recognizer;
        use crate::recognizers::iban::IbanRecognizer;

        // FAKE: the specimen FR IBAN, cut by nine zero-width spaces.
        let text = format!("FR76 3000 6000 0112 3456{}7890 189", "\u{200B}".repeat(9));
        assert!(IbanRecognizer::new().analyze(&text).is_empty());
    }

    #[test]
    fn an_iban_split_by_a_blank_paragraph_does_not_merge() {
        use crate::recognizer::Recognizer;
        use crate::recognizers::iban::IbanRecognizer;

        // FAKE: the specimen FR IBAN, cut by a blank paragraph. Neither half is
        // an IBAN, and no span may bridge the two.
        let text = "FR76 3000 6000 0112 3456\n\n\n7890 189";
        assert!(IbanRecognizer::new().analyze(text).is_empty());
    }

    #[test]
    fn two_numbers_split_by_a_blank_paragraph_do_not_merge() {
        use crate::recognizer::Recognizer;
        use crate::recognizers::phone::PhoneRecognizer;

        // FAKE: two numbers in the 555 fiction range, a blank paragraph apart.
        let text = "+1 (202) 555-0142\n\n\n+1 (202) 555-0199";
        let spans = PhoneRecognizer::new().analyze(text);
        assert!(!spans.is_empty(), "{spans:?}");
        for span in spans {
            let found = &text[span.start..span.end];
            assert!(!found.contains('\n'), "{found:?}");
        }
    }

    #[test]
    fn masking_never_spans_past_the_identifier_and_its_folds() {
        use crate::recognizer::Recognizer;
        use crate::recognizers::iban::IbanRecognizer;

        // FAKE: a wrapped specimen IBAN followed by a long blank region.
        let wrapped = "FR76 3000 6000 0112 3456\n7890 189";
        let text = format!("{wrapped}{}", " ".repeat(10_000));
        let spans = IbanRecognizer::new().analyze(&text);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(&text[spans[0].start..spans[0].end], wrapped);
    }
}
