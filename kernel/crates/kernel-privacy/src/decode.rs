//! Pre-processing with an exact offset map back to the original bytes.
//!
//! Messy e-mail reaches the kernel through HTML-to-text conversions and link
//! rewriting, so a value the deterministic recognisers would catch in clear
//! text arrives encoded:
//!
//! * HTML entities (`&nbsp;`, `&amp;`, `&#39;`, `&#x27;`, `&eacute;`) split a
//!   value or hide its separators;
//! * percent escapes inside a URL (`freya.halloran%40example.invalid`,
//!   `nom=Oc%C3%A9ane+Mabille`) hide the address or the name;
//! * a URL packs a path and query into one token whose `-`, `_`, `.`, `+`
//!   separators the detectors must treat as word breaks.
//!
//! [`DecodedText`] builds a decoded view of the input and keeps, for every
//! character of that view, the original byte range it came from. A detection
//! runs on the decoded view; its span is mapped back with
//! [`DecodedText::source_bounds`] and the caller verifies the bytes as usual.
//! Percent escapes are decoded only inside a token that carries a URL scheme,
//! so a stray `%40` in prose is not silently turned into an address; named
//! entities are decoded everywhere because they are unambiguous.
//!
//! The view is for detection: token markers (`⟦…⟧`, a lone bracket) and
//! default-ignorable characters (zero-width space, soft hyphen) are dropped and
//! their bytes go to the next character, so `sk-ab⟦T⟧cd` reads `sk-abcd`.
//!
//! The module also exposes [`DecodedText::url_segments`], which walks the URLs
//! of the source and yields their path and query values split into scannable
//! segments with their original byte offsets.

use crate::anonymize::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};

mod entities;

type EscapeParser<'a> = dyn Fn(&str, usize) -> Option<(char, usize)> + 'a;
type ViewVisitor<'a> = dyn FnMut(&str, &[usize], &[(usize, usize)]) + 'a;

/// A decoded view of a text plus the map from decoded characters back to the
/// original byte ranges.
pub struct DecodedText {
    text: String,
    /// Decoded byte offset of each decoded character.
    char_starts: Vec<usize>,
    /// Original byte range of each decoded character.
    char_bounds: Vec<(usize, usize)>,
    /// Source tokens still encoded after [`MAX_PASSES`]: masked whole.
    unresolved: Vec<(usize, usize)>,
    /// Whether a `⟦…⟧` pair was dropped with its content.
    dropped_marker_body: bool,
    /// Source range of every dropped marker: a lone bracket, or a pair with its
    /// content, written plainly or as entities.
    markers: Vec<(usize, usize)>,
    /// What this view did with the markers.
    mode: Markers,
}

impl DecodedText {
    /// Build the decoded view of `source`.
    ///
    /// HTML entities are decoded everywhere; percent escapes only inside a URL
    /// token. Decoding repeats to a fixed point, at most [`MAX_PASSES`] times,
    /// so a nested value (`%2540` → `%40` → `@`, `&AMP;eacute;` → `é`) folds to
    /// its final character. Each pass is linear, so the whole is linear. Every valid escape
    /// decodes on its own and each invalid one stays literal; the whole percent
    /// run is attributed to every character it produced, so a detection that
    /// covers only part of a partially decoded run still maps back to all of its
    /// source bytes.
    pub fn new(source: &str) -> Self {
        Self::build(source, Markers::Drop)
    }

    /// The same view, but a `⟦…⟧` pair loses only its brackets: a value written
    /// inside one (`⟦sk-…⟧`) is still read.
    pub fn brackets_only(source: &str) -> Self {
        Self::build(source, Markers::Brackets)
    }

    /// The same view, but each bracket reads as a space: a value it touches
    /// keeps its word boundary (`texte⟦sk-…⟧` reads `texte sk-… `).
    pub fn brackets_as_spaces(source: &str) -> Self {
        Self::build(source, Markers::Space)
    }

    /// Decode extra escapes; `brackets_only` retains marker bodies.
    pub fn escaped(source: &str, brackets_only: bool) -> Option<Self> {
        let mode = [Markers::Drop, Markers::Brackets][usize::from(brackets_only)];
        let has_common = |text: &str| {
            text.match_indices(['\\', '%'])
                .any(|(at, _)| common_escape(text, at).is_some())
        };
        let mut seen = has_common(source);
        let (mut view, settled) =
            Self::build_inner(source, mode, Some(&|_, _| None), &mut |text, _, _| {
                seen |= has_common(text);
            });
        if !settled && !source.is_empty() {
            view.unresolved.push((0, source.len()));
        }
        (seen || !settled).then_some(view)
    }

    fn build(source: &str, mode: Markers) -> Self {
        Self::build_inner(source, mode, None, &mut |_, _, _| {}).0
    }

    /// Whether decoding leaves `source` alone: only an ASCII text with no
    /// entity (`&`) and no percent escape decodes to itself.
    pub(crate) fn is_unchanged(source: &str) -> bool {
        source.is_ascii() && !source.bytes().any(|byte| matches!(byte, b'&' | b'%'))
    }

    /// Visit each decoded view of a known-secret run, mapped back to `source`.
    /// Returns false if decoding cannot settle within the shared limits.
    pub fn scan_known_secret(
        source: &str,
        escape: &EscapeParser<'_>,
        visit: &mut ViewVisitor<'_>,
    ) -> bool {
        if source.len() > MAX_SECRET_DECODE_WORK {
            return false;
        }
        Self::build_inner(source, Markers::Drop, Some(escape), visit).1
    }

    fn build_inner(
        source: &str,
        mode: Markers,
        escape: Option<&EscapeParser<'_>>,
        visit: &mut ViewVisitor<'_>,
    ) -> (Self, bool) {
        let mut dropped_marker_body = false;
        let mut text = source.to_string();
        let mut char_starts: Vec<usize> = Vec::with_capacity(source.len());
        let mut char_bounds: Vec<(usize, usize)> = Vec::with_capacity(source.len());
        for (index, ch) in source.char_indices() {
            char_starts.push(index);
            char_bounds.push((index, index + ch.len_utf8()));
        }
        let mut converged = false;
        let mut spent = 0usize;
        let budget = source
            .len()
            .saturating_mul(MAX_PASSES)
            .min(MAX_SECRET_DECODE_WORK);
        let mut markers: Vec<(usize, usize)> = Vec::new();
        for _ in 0..MAX_PASSES {
            if escape.is_some() && spent.saturating_add(text.len().saturating_mul(2)) > budget {
                break;
            }
            spent = spent.saturating_add(text.len());
            let (decoded, local_bounds, dropped, local_markers) = decode_once(&text, mode, escape);
            if decoded == text {
                converged = true;
                break;
            }
            if escape.is_some() && spent.saturating_add(decoded.len().saturating_mul(2)) > budget {
                break;
            }
            spent = spent.saturating_add(decoded.len());
            dropped_marker_body |= dropped;
            for (start, end) in local_markers {
                let first = char_starts.partition_point(|offset| *offset < start);
                let after = char_starts.partition_point(|offset| *offset < end);
                markers.push((char_bounds[first].0, char_bounds[after - 1].1));
            }
            let mut next_starts: Vec<usize> = Vec::with_capacity(decoded.len());
            let mut next_bounds: Vec<(usize, usize)> = Vec::with_capacity(decoded.len());
            // Local bounds only move forward, so two cursors replace a binary
            // search per character.
            let (mut first, mut after) = (0usize, 0usize);
            for ((offset, _), (start, end)) in
                decoded.char_indices().zip(local_bounds.iter().copied())
            {
                while first < char_starts.len() && char_starts[first] < start {
                    first += 1;
                }
                after = after.max(first);
                while after < char_starts.len() && char_starts[after] < end {
                    after += 1;
                }
                debug_assert!(
                    first < after,
                    "a decoded char maps to at least one source char"
                );
                next_starts.push(offset);
                next_bounds.push((char_bounds[first].0, char_bounds[after - 1].1));
            }
            text = decoded;
            char_starts = next_starts;
            char_bounds = next_bounds;
            if escape.is_some() {
                visit(&text, &char_starts, &char_bounds);
            }
        }
        if !converged && escape.is_some() && spent.saturating_add(text.len()) <= budget {
            converged = decode_once(&text, mode, escape).0 == text;
        }
        let mut view = Self {
            text,
            char_starts,
            char_bounds,
            unresolved: Vec::new(),
            dropped_marker_body,
            markers,
            mode,
        };
        view.markers.sort_unstable();
        if !converged && escape.is_none() {
            view.unresolved = view.unresolved_tokens(source, mode);
        }
        (view, converged)
    }

    /// Fail closed at the pass cap: every whitespace-delimited source token a
    /// further pass would still change.
    fn unresolved_tokens(&self, source: &str, mode: Markers) -> Vec<(usize, usize)> {
        let (decoded, local_bounds, _, _) = decode_once(&self.text, mode, None);
        let mut tokens: Vec<(usize, usize)> = Vec::new();
        for (ch, (start, end)) in decoded.chars().zip(local_bounds) {
            let same = self.text[start..end] == *ch.encode_utf8(&mut [0; 4]);
            let Some((from, to)) = self.source_bounds(start, end).filter(|_| !same) else {
                continue;
            };
            if tokens.last().is_some_and(|last| from < last.1) {
                continue;
            }
            let from = source[..from]
                .char_indices()
                .rev()
                .find(|(_, c)| c.is_whitespace())
                .map_or(0, |(at, c)| at + c.len_utf8());
            let to = source[to..]
                .find(char::is_whitespace)
                .map_or(source.len(), |at| to + at);
            tokens.push((from, to));
        }
        tokens
    }

    /// Source ranges still encoded when decoding stopped at [`MAX_PASSES`].
    pub fn unresolved(&self) -> &[(usize, usize)] {
        &self.unresolved
    }

    /// Whether a `⟦…⟧` pair was dropped with its content.
    pub fn dropped_marker_body(&self) -> bool {
        self.dropped_marker_body
    }

    /// Source range of every dropped token marker (a lone `⟦` or `⟧`, or a
    /// `⟦…⟧` pair with its content), sorted by start.
    pub fn markers(&self) -> &[(usize, usize)] {
        &self.markers
    }

    /// Whether this view deletes the markers (dropped, or brackets only),
    /// rather than reading them as spaces.
    pub fn mode_drops_brackets(&self) -> bool {
        self.mode != Markers::Space
    }

    /// Whether the dropped marker at source range `marker` sits between two
    /// letters of this view (`chimioth⟦X⟧érapie`, `sk-abc⟦X def⟧` read with only
    /// the brackets gone): dropping it splices one word out of two.
    pub fn marker_joins_letters(&self, marker: (usize, usize)) -> bool {
        let letter = |index: usize| {
            self.char_starts
                .get(index)
                .and_then(|&at| self.text[at..].chars().next())
                .is_some_and(char::is_alphabetic)
        };
        // A dropped marker's bytes go to the next kept character.
        let after = self.char_bounds.partition_point(|b| b.1 <= marker.1);
        let before = self.char_bounds.partition_point(|b| b.1 <= marker.0);
        before > 0 && letter(before - 1) && letter(after)
    }

    /// The decoded text to scan.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The decoded byte offset of each decoded character.
    pub fn char_starts(&self) -> &[usize] {
        &self.char_starts
    }

    /// The original byte range of each decoded character.
    pub fn char_bounds(&self) -> &[(usize, usize)] {
        &self.char_bounds
    }

    /// Map a byte range in the decoded view back to the original bytes.
    ///
    /// Returns `None` when the range is empty, out of bounds or not on a char
    /// boundary. A range that spans a decoded entity returns the full original
    /// range of that entity, so masking covers every source byte of the value.
    pub fn source_bounds(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        if start >= end || end > self.text.len() {
            return None;
        }
        if !self.text.is_char_boundary(start) || !self.text.is_char_boundary(end) {
            return None;
        }
        let first = self.char_starts.partition_point(|offset| *offset < start);
        let after = self.char_starts.partition_point(|offset| *offset < end);
        if first >= after {
            return None;
        }
        let (orig_start, _) = self.char_bounds[first];
        let (_, orig_end) = self.char_bounds[after - 1];
        if orig_start >= orig_end {
            return None;
        }
        Some((orig_start, orig_end))
    }

    /// The path and query segments of every URL in `source`, with their
    /// original byte offsets.
    ///
    /// A segment is a maximal run of word characters; `-`, `_`, `.`, `+`, `/`,
    /// `?`, `&` and `=` all separate segments, so `linkedin.example.invalid/in/
    /// jules-ferrand` yields `linkedin`, `example`, `invalid`, `in`, `jules`
    /// and `ferrand`. Values that decode to nothing are skipped.
    pub fn url_segments(source: &str) -> Vec<(String, usize, usize)> {
        let mut segments = Vec::new();
        for (start, end) in url_ranges(source) {
            let decoded = DecodedText::new(&source[start..end]);
            let mut cursor = 0usize;
            let mut segment_start: Option<usize> = None;
            for (offset, ch) in decoded.text().char_indices() {
                if ch.is_alphanumeric() {
                    if segment_start.is_none() {
                        segment_start = Some(offset);
                    }
                } else if let Some(begin) = segment_start.take() {
                    if let Some((orig_start, orig_end)) = decoded.source_bounds(begin, offset) {
                        segments.push((
                            source[start + orig_start..start + orig_end].to_string(),
                            start + orig_start,
                            start + orig_end,
                        ));
                    }
                }
                cursor = offset + ch.len_utf8();
            }
            if let Some(begin) = segment_start {
                if let Some((orig_start, orig_end)) = decoded.source_bounds(begin, cursor) {
                    segments.push((
                        source[start + orig_start..start + orig_end].to_string(),
                        start + orig_start,
                        start + orig_end,
                    ));
                }
            }
        }
        segments
    }
}

/// The whitespace-delimited ranges of `source` that one more decoding pass
/// would still change, whether or not [`MAX_PASSES`] was reached.
///
/// This is the same question [`DecodedText::unresolved`] asks of a view the
/// *decoder* stopped on, asked here of any text. The registry's composition
/// (NORM-2) stops after a fixed number of rounds of decode and fold, so a
/// spelling deeper than that is not read: the ranges this returns are masked
/// whole rather than left clear.
pub(crate) fn tokens_still_encoded(source: &str) -> Vec<(usize, usize)> {
    let (decoded, local_bounds, _, _) = decode_once(source, Markers::Drop, None);
    let mut tokens: Vec<(usize, usize)> = Vec::new();
    for (ch, (start, end)) in decoded.chars().zip(local_bounds) {
        let mut bytes = [0u8; 4];
        let unchanged = source
            .get(start..end)
            .is_some_and(|found| found == ch.encode_utf8(&mut bytes));
        if unchanged || tokens.last().is_some_and(|last| start < last.1) {
            continue;
        }
        let from = source[..start]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map_or(0, |(at, c)| at + c.len_utf8());
        let to = source[end..]
            .find(char::is_whitespace)
            .map_or(source.len(), |at| end + at);
        tokens.push((from, to));
    }
    tokens
}

/// Decoding passes before the view is taken as final. Real mail nests one or
/// two layers; the cap keeps adversarial nesting linear.
pub const MAX_PASSES: usize = 16;

/// Ceiling used by kernel secret-echo decoding; reads and scans are charged.
pub const MAX_SECRET_DECODE_WORK: usize = 4 * 1024 * 1024;

/// What a view does with a token marker.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Markers {
    /// A `⟦…⟧` pair goes with its content, a lone bracket alone.
    Drop,
    /// Only the brackets go.
    Brackets,
    /// Each bracket reads as a space.
    Space,
}

/// One pass: the decoded text, the source range of each of its characters,
/// whether a `⟦…⟧` pair was dropped with its content, and the dropped markers.
type Pass = (String, Vec<(usize, usize)>, bool, Vec<(usize, usize)>);

/// One decoding pass over `source`.
///
/// Returns the decoded text and, for every character of it, the byte range in
/// `source` it came from. Named and numeric entities are decoded everywhere;
/// percent escapes only inside a URL token; markers and hidden characters are
/// dropped (see the module docs). A malformed escape stays literal and
/// never blocks the valid escapes around it, and every character a percent run
/// produced carries the run's full source range (conservative bounds).
fn decode_once(source: &str, mode: Markers, escape: Option<&EscapeParser<'_>>) -> Pass {
    let urls = url_ranges(source);
    let mut text = String::with_capacity(source.len());
    let mut bounds: Vec<(usize, usize)> = Vec::with_capacity(source.len());
    let mut index = 0usize;
    // `urls` is sorted and disjoint, so a single forward cursor replaces a scan
    // of every range at every escape: the pass stays linear on a text with many
    // escapes and many URLs.
    let mut url_cursor = 0usize;
    // Start of the dropped bytes not yet attributed to a kept character.
    let mut hidden: Option<usize> = None;
    // The nearest `⟧` at or after the cursor, found once per bracket: linear.
    let mut next_close: Option<Option<usize>> = None;
    let mut dropped_body = false;
    let mut markers: Vec<(usize, usize)> = Vec::new();
    while index < source.len() {
        while url_cursor < urls.len() && index >= urls[url_cursor].1 {
            url_cursor += 1;
        }
        let in_url = url_cursor < urls.len() && index >= urls[url_cursor].0;
        let ch = source[index..]
            .chars()
            .next()
            .expect("index is on a char boundary");
        if ch == '\\' || ch == '%' {
            if let Some((decoded, end)) = escape
                .and_then(|parse| {
                    common_escape(source, index)
                        .or_else(|| (ch == '\\').then(|| parse(source, index)).flatten())
                })
                .filter(|(_, end)| *end > index && source.is_char_boundary(*end))
            {
                push_decoded(
                    &mut text,
                    &mut bounds,
                    &mut hidden,
                    decoded.encode_utf8(&mut [0; 4]),
                    (index, end),
                );
                index = end;
                continue;
            }
        }
        // A `⟦…⟧` pair (nearest `⟧`, any content) or a lone bracket is dropped.
        // A bracket an entity produced is kept for the next pass.
        if ch == PLACEHOLDER_OPEN || ch == PLACEHOLDER_CLOSE {
            let mut end = index + ch.len_utf8();
            markers.push((index, end));
            if mode == Markers::Space {
                push_decoded(&mut text, &mut bounds, &mut hidden, " ", (index, end));
                index = end;
                continue;
            }
            hidden.get_or_insert(index);
            if ch == PLACEHOLDER_OPEN && mode == Markers::Drop {
                if next_close.is_none_or(|close| close.is_some_and(|at| at < end)) {
                    next_close = Some(source[end..].find(PLACEHOLDER_CLOSE).map(|at| end + at));
                }
                if let Some(Some(close)) = next_close {
                    dropped_body = true;
                    end = close + PLACEHOLDER_CLOSE.len_utf8();
                }
            }
            markers.last_mut().expect("just pushed").1 = end;
            index = end;
            continue;
        }
        // Percent run inside a URL token.
        if ch == '%' && (in_url || escape.is_some()) {
            let run_end = percent_run_end(source, index).max(index + 1);
            let (decoded, _) = decode_percent_run(&source[index..run_end]);
            push_decoded(
                &mut text,
                &mut bounds,
                &mut hidden,
                &decoded,
                (index, run_end),
            );
            index = run_end;
            continue;
        }
        // Named or numeric HTML entity.
        if ch == '&' {
            if let Some((decoded, consumed)) = decode_entity(source, index) {
                let end = index + consumed;
                push_decoded(&mut text, &mut bounds, &mut hidden, &decoded, (index, end));
                index = end;
                continue;
            }
        }
        let end = index + ch.len_utf8();
        push_decoded(
            &mut text,
            &mut bounds,
            &mut hidden,
            ch.encode_utf8(&mut [0; 4]),
            (index, end),
        );
        index = end;
    }
    // Dropped bytes at the end belong to the last kept character.
    if let (Some(_), Some(last)) = (hidden, bounds.last_mut()) {
        last.1 = source.len();
    }
    (text, bounds, dropped_body, markers)
}

/// The additional escapes read by both the privacy and known-secret views.
fn common_escape(source: &str, at: usize) -> Option<(char, usize)> {
    let bytes = source.as_bytes();
    match (*bytes.get(at)?, *bytes.get(at + 1)?) {
        (b'\\', b'/') => Some(('/', at + 2)),
        (b'\\', b'0'..=b'7') => {
            let mut end = at + 1;
            let mut value = 0u32;
            while end < (at + 4).min(bytes.len()) && (b'0'..=b'7').contains(&bytes[end]) {
                value = value * 8 + u32::from(bytes[end] - b'0');
                end += 1;
            }
            (value <= 0o377).then_some((char::from_u32(value)?, end))
        }
        (b'%', b'u' | b'U') => {
            let unit = |start: usize| -> Option<u32> {
                bytes
                    .get(start..start + 4)?
                    .iter()
                    .try_fold(0, |n, b| Some(n * 16 + u32::from(hex_value(*b)?)))
            };
            let mut value = unit(at + 2)?;
            let mut end = at + 6;
            if (0xD800..=0xDBFF).contains(&value) {
                if !matches!(bytes.get(end..end + 2), Some([b'%', b'u' | b'U'])) {
                    return None;
                }
                let low = unit(end + 2).filter(|n| (0xDC00..=0xDFFF).contains(n))?;
                value = 0x10000 + ((value - 0xD800) << 10) + low - 0xDC00;
                end += 6;
            }
            Some((char::from_u32(value)?, end))
        }
        _ => None,
    }
}

/// Whether the known-secret view can decode an escape starting at `at`.
pub fn known_escape_at(source: &str, at: usize, escape: &EscapeParser<'_>) -> bool {
    let Some(rest) = source.get(at..) else {
        return false;
    };
    if common_escape(rest, 0).is_some() || (rest.starts_with('\\') && escape(rest, 0).is_some()) {
        return true;
    }
    if rest.starts_with('&') {
        return decode_entity(rest, 0).is_some();
    }
    if rest.starts_with('%') {
        let probe = rest.get(..12).unwrap_or(rest);
        let end = percent_run_end(probe, 0);
        return decode_percent_run(&probe[..end]).1;
    }
    false
}

/// Append `value` to the decoded view, attributing each char to `bound`. A
/// default-ignorable char (zero-width space, soft hyphen) is dropped; its bytes
/// go to the next kept char.
fn push_decoded(
    text: &mut String,
    bounds: &mut Vec<(usize, usize)>,
    hidden: &mut Option<usize>,
    value: &str,
    bound: (usize, usize),
) {
    for ch in value.chars() {
        if crate::contacts::fold::is_default_ignorable(ch) {
            hidden.get_or_insert(bound.0);
            continue;
        }
        text.push(ch);
        bounds.push((
            hidden.take().map_or(bound.0, |start| start.min(bound.0)),
            bound.1,
        ));
    }
}

/// The byte range of the percent-escape run that starts at `index` (a `%`).
///
/// A run is the maximal sequence of `%` units, each followed by zero, one or two
/// hex digits, so a truncated escape such as `%8` stays inside the run it
/// follows instead of splitting it.
fn percent_run_end(source: &str, index: usize) -> usize {
    let bytes = source.as_bytes();
    let mut cursor = index;
    while cursor < bytes.len() && bytes[cursor] == b'%' {
        cursor += 1;
        let mut taken = 0;
        while taken < 2 && cursor < bytes.len() && hex_value(bytes[cursor]).is_some() {
            cursor += 1;
            taken += 1;
        }
    }
    cursor
}

/// Decode the percent-escape run `run` (which starts with `%`).
///
/// Every escape that yields a printable ASCII byte or a valid multi-byte UTF-8
/// sequence decodes; anything else — a truncated `%8`, a `%ZZ`, a lone
/// continuation byte — is kept exactly as written. Returns the decoded text and
/// whether at least one escape decoded.
fn decode_percent_run(run: &str) -> (String, bool) {
    let bytes = run.as_bytes();
    let mut out = String::with_capacity(run.len());
    let mut changed = false;
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            let ch = run[index..]
                .chars()
                .next()
                .expect("index is on a char boundary");
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        let first = bytes
            .get(index + 1)
            .copied()
            .and_then(hex_value)
            .zip(bytes.get(index + 2).copied().and_then(hex_value));
        let Some((high, low)) = first else {
            // `%` with no hex digit after it: literal.
            out.push('%');
            index += 1;
            continue;
        };
        let byte = high * 16 + low;
        if byte < 0x80 {
            if (0x20..=0x7E).contains(&byte) {
                out.push(byte as char);
                changed = true;
            } else {
                out.push_str(&run[index..index + 3]);
            }
            index += 3;
            continue;
        }
        let Some(width) = utf8_width(byte) else {
            out.push_str(&run[index..index + 3]);
            index += 3;
            continue;
        };
        // Collect the continuation escapes of a multi-byte sequence.
        let mut sequence = vec![byte];
        let mut cursor = index + 3;
        let mut complete = true;
        while sequence.len() < width {
            let Some(continuation) =
                bytes
                    .get(cursor)
                    .filter(|byte| **byte == b'%')
                    .and_then(|_| {
                        bytes
                            .get(cursor + 1)
                            .copied()
                            .and_then(hex_value)
                            .zip(bytes.get(cursor + 2).copied().and_then(hex_value))
                    })
            else {
                complete = false;
                break;
            };
            let value = continuation.0 * 16 + continuation.1;
            if !(0x80..=0xBF).contains(&value) {
                complete = false;
                break;
            }
            sequence.push(value);
            cursor += 3;
        }
        match (complete, std::str::from_utf8(&sequence)) {
            (true, Ok(decoded)) => {
                out.push_str(decoded);
                changed = true;
                index = cursor;
            }
            _ => {
                out.push_str(&run[index..index + 3]);
                index += 3;
            }
        }
    }
    (out, changed)
}

/// The UTF-8 sequence width a leading byte announces, when it is a valid one.
fn utf8_width(byte: u8) -> Option<usize> {
    match byte {
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

/// The byte ranges of every whitespace-delimited token that carries a URL
/// scheme (`://`).
pub fn url_ranges(source: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        let mut end = index;
        while end < bytes.len()
            && !bytes[end].is_ascii_whitespace()
            && !matches!(bytes[end], b'<' | b'>' | b'"' | b'\'' | b')' | b'(')
        {
            end += 1;
        }
        if source[start..end].contains("://") {
            ranges.push((start, end));
        }
        index = end.max(index + 1);
    }
    ranges
}

/// The numeric value of a hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The longest entity body we decode, in bytes.
pub(crate) const MAX_ENTITY_BODY: usize = 34;

/// Windows-1252 characters HTML5 substitutes for numeric references
/// `&#128;` to `&#159;`, in order; a C1 control reads U+FFFD.
const C1_REPLACEMENTS: &str = "€\u{FFFD}‚ƒ„…†‡ˆ‰Š‹Œ\u{FFFD}Ž\u{FFFD}\u{FFFD}‘’“”•–—˜™š›œ\u{FFFD}žŸ";

/// Decode the entity that starts at `index` (which holds `&`).
///
/// Returns the decoded string and the source bytes consumed. A numeric reference
/// follows HTML5: any digits (leading zeros too), `;` optional, an invalid value
/// reads U+FFFD. A named entity is any HTML5 name in any case; without `;` only a
/// legacy name decodes, the longest one at the start of the run. Anything else
/// returns `None`, so its bytes stay in place.
fn decode_entity(source: &str, index: usize) -> Option<(String, usize)> {
    let bytes = &source.as_bytes()[index + 1..];
    if bytes.first() == Some(&b'#') {
        let hex = matches!(bytes.get(1), Some(b'x' | b'X'));
        let digits_at = if hex { 2 } else { 1 };
        let radix = if hex { 16 } else { 10 };
        // Every digit is consumed, so a long run is read once, not per `&`.
        let (count, code) = bytes[digits_at..]
            .iter()
            .map_while(|b| (*b as char).to_digit(radix))
            .fold((0, 0u32), |(n, code), digit| {
                (
                    n + 1,
                    code.saturating_mul(radix)
                        .saturating_add(digit)
                        .min(0x11_0000),
                )
            });
        if count == 0 {
            return None;
        }
        let used = digits_at + count;
        let used = used + usize::from(bytes.get(used) == Some(&b';'));
        let ch = match code {
            0x80..=0x9F => C1_REPLACEMENTS
                .chars()
                .nth((code - 0x80) as usize)
                .unwrap_or('\u{FFFD}'),
            _ => char::from_u32(code)
                .filter(|ch| *ch != '\0')
                .unwrap_or('\u{FFFD}'),
        };
        return Some((ch.to_string(), used + 1));
    }
    // A longer run is read for its longest known prefix, as HTML5 does.
    let name_len = bytes
        .iter()
        .take(MAX_ENTITY_BODY)
        .take_while(|b| b.is_ascii_alphanumeric())
        .count();
    let name = &source[index + 1..index + 1 + name_len];
    let lower = name.to_ascii_lowercase();
    if bytes.get(name_len) == Some(&b';') {
        if let Some(value) = named_entity(name, &lower, true) {
            return Some((value.to_string(), name_len + 2));
        }
    }
    // No `;`: the longest legacy name at the start of the run.
    (1..=name_len).rev().find_map(|len| {
        named_entity(&name[..len], &lower[..len], false).map(|value| (value.to_string(), len + 1))
    })
}

/// Names the kernel decoded without `;` before the full table, though HTML5
/// reads them only with it: they stay decoded, so no view loses a character.
const NO_SEMICOLON_EXTRA: &[&str] = &[
    "applyfunction",
    "apos",
    "bull",
    "emsp",
    "ensp",
    "euro",
    "hellip",
    "invisiblecomma",
    "invisibletimes",
    "ldquo",
    "lrm",
    "lsquo",
    "mdash",
    "ndash",
    "negativemediumspace",
    "negativethickspace",
    "negativethinspace",
    "negativeverythinspace",
    "nobreak",
    "nonbreakingspace",
    "rdquo",
    "rlm",
    "rsquo",
    "thinsp",
    "trade",
    "zerowidthspace",
    "zwj",
    "zwnj",
];

/// The HTML5 named character reference `name` (without `;`, `lower` is its
/// ASCII lowercase): an exact match first, then any case (`&EACUTE;` reads
/// `é`). Without its `;` (`semicolon` false) a name decodes only when HTML5
/// allows it (`&eacute`, `&amp`) or the kernel always has. Two binary searches over the generated table: linear
/// decoding stays linear.
fn named_entity(name: &str, lower: &str, semicolon: bool) -> Option<&'static str> {
    let find = |table: &'static [(&str, &str, bool)], key: &str| {
        table
            .binary_search_by(|(entry, _, _)| entry.cmp(&key))
            .ok()
            .map(|at| table[at])
    };
    let (_, value, legacy) =
        find(entities::ENTITIES, name).or_else(|| find(entities::FOLDED, lower))?;
    (semicolon || legacy || NO_SEMICOLON_EXTRA.contains(&lower)).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn decode(source: &str) -> String {
        DecodedText::new(source).text().to_string()
    }

    #[test]
    fn named_and_numeric_entities_decode() {
        assert_eq!(decode("Hi&nbsp;Tobi"), "Hi\u{00A0}Tobi");
        assert_eq!(decode("a&amp;b"), "a&b");
        assert_eq!(decode("caf&#233;"), "café");
        assert_eq!(decode("caf&#xe9;"), "café");
        assert_eq!(decode("&eacute;lodie"), "élodie");
        // An unknown entity keeps its bytes.
        assert_eq!(decode("a&unknown;b"), "a&unknown;b");
        assert_eq!(decode("a & b"), "a & b");
    }

    #[test]
    fn percent_escapes_decode_only_inside_urls() {
        assert_eq!(
            decode("https://promo.example.invalid/u?e=freya%40example.invalid"),
            "https://promo.example.invalid/u?e=freya@example.invalid"
        );
        // Outside a URL the escape is left alone.
        assert_eq!(decode("just %40 here"), "just %40 here");
        // A multi-byte UTF-8 run decodes to one character.
        assert_eq!(
            decode("https://x.invalid/?nom=Oc%C3%A9ane"),
            "https://x.invalid/?nom=Océane"
        );
    }

    #[test]
    fn source_bounds_map_back_to_exact_bytes() {
        let source = "Hi&nbsp;Tobi";
        let decoded = DecodedText::new(source);
        let start = decoded.text().find("Tobi").expect("name");
        let (begin, end) = decoded.source_bounds(start, start + 4).expect("maps back");
        assert_eq!(&source[begin..end], "Tobi");
        let nbsp = decoded.text().find('\u{00A0}').expect("space");
        let (begin, end) = decoded
            .source_bounds(nbsp, nbsp + '\u{00A0}'.len_utf8())
            .expect("maps entity");
        assert_eq!(&source[begin..end], "&nbsp;");
    }

    #[test]
    fn percent_bounds_cover_the_escaped_bytes() {
        let source = "https://x.invalid/u?e=freya%40example.invalid";
        let decoded = DecodedText::new(source);
        let at = decoded.text().find('@').expect("decoded at");
        let (begin, end) = decoded.source_bounds(at, at + 1).expect("maps back");
        assert_eq!(&source[begin..end], "%40");
    }

    #[test]
    fn malformed_escapes_stay_literal_and_do_not_hide_valid_ones() {
        // A truncated multi-byte escape is kept whole.
        assert_eq!(
            decode("https://x.invalid/a?n=%E2%8"),
            "https://x.invalid/a?n=%E2%8"
        );
        // A non-hex escape is literal while the valid escapes around it decode.
        assert_eq!(
            decode("https://x.invalid/a?n=%41%ZZ%42"),
            "https://x.invalid/a?n=A%ZZB"
        );
        // A lone `%` stays as written.
        assert_eq!(decode("https://x.invalid/a?n=%"), "https://x.invalid/a?n=%");
    }

    #[test]
    fn a_valid_escape_inside_a_broken_run_still_decodes() {
        let source = "https://x.invalid/u?e=freya%40%E2%8!example.invalid";
        let decoded = DecodedText::new(source);
        assert!(
            decoded.text().contains("freya@%E2%8!example.invalid"),
            "decoded = {}",
            decoded.text()
        );
        // The decoded `@` maps back to the whole broken run, so masking it
        // covers every byte of the run.
        let at = decoded.text().find('@').expect("decoded at");
        let (begin, end) = decoded.source_bounds(at, at + 1).expect("maps back");
        assert_eq!(&source[begin..end], "%40%E2%8");
    }

    #[test]
    fn nested_escapes_unfold_to_a_fixed_point() {
        let source = "https://x.invalid/u?e=freya%2540example.invalid";
        let decoded = DecodedText::new(source);
        assert_eq!(
            decoded.text(),
            "https://x.invalid/u?e=freya@example.invalid"
        );
        // One decoded char maps back to the full doubly encoded escape.
        let at = decoded.text().find('@').expect("decoded at");
        let (begin, end) = decoded.source_bounds(at, at + 1).expect("maps back");
        assert_eq!(&source[begin..end], "%2540");
        // A triple encoding folds too: decoding runs to a fixed point.
        assert_eq!(
            decode("https://x.invalid/u?e=freya%252540example.invalid"),
            "https://x.invalid/u?e=freya@example.invalid"
        );
    }

    #[test]
    fn numeric_references_follow_html5() {
        assert_eq!(decode("sk&#0045pq&#X02d;pq&#x2Dpq"), "sk-pq-pq-pq");
        // Zero, surrogates and out-of-range values read U+FFFD; C1 values read
        // their Windows-1252 character.
        assert_eq!(
            decode("a&#0;b&#xD800;c&#99999999999;d"),
            "a\u{FFFD}b\u{FFFD}c\u{FFFD}d"
        );
        assert_eq!(decode("a&#150;b"), "a–b");
        // `&#` with no digit stays literal.
        assert_eq!(decode("a&#;b&#x;c"), "a&#;b&#x;c");
        // Named entities match in any case; nested encodings fold to a fixed point.
        assert_eq!(
            decode("a&AMP;b R&D chimioth&AMP;eacute;rapie"),
            "a&b R&D chimiothérapie"
        );
        assert_eq!(decode("sk&#38;#38;#x2d;x"), "sk-x");
    }

    #[test]
    fn markers_and_hidden_characters_are_dropped_and_mapped_back() {
        let source = "sk-abc&#10214;PERSON_ABCDEFABCDEF&#10215;def\u{200B}g&shy;h⟦⟦X⟧i⟧";
        let decoded = DecodedText::new(source);
        assert_eq!(decoded.text(), "sk-abcdefghi");
        // The decoded value maps back to every source byte, markers included.
        assert_eq!(decoded.source_bounds(0, 12), Some((0, source.len())));
        // Any pair goes, to the nearest `⟧`; the bracket-only view keeps its content.
        let long = format!("chimioth⟦{}⟧érapie a⟦A B⟧b", "A".repeat(65));
        assert_eq!(decode(&long), "chimiothérapie ab");
        let kept = DecodedText::brackets_only("a⟦A B⟧b");
        assert_eq!(kept.text(), "aA Bb");
        // Invisible named entities, `&shy` before a long run, short names only with `;`.
        let source = format!("a&ZeroWidthSpace;b&ZWJ;c&it;d&shy{}", "e".repeat(40));
        assert_eq!(decode(&source), format!("abcd{}", "e".repeat(40)));
        assert_eq!(decode("a&itb"), "a&itb");
        assert_eq!(decode("a⟧b⟧c"), "abc");
    }

    #[test]
    fn every_html5_name_decodes_and_only_legacy_names_need_no_semicolon() {
        for table in [entities::ENTITIES, entities::FOLDED] {
            assert!(table.windows(2).all(|pair| pair[0].0 < pair[1].0));
        }
        assert_eq!(entities::ENTITIES.len(), 2125);
        assert_eq!(
            decode("plju&ccaron;ni PLJU&Ccaron;NI &CCARON;"),
            "pljučni PLJUČNI č"
        );
        assert_eq!(decode("t&uuml;d&odblac;gyullad&aacute;s"), "tüdőgyulladás");
        assert_eq!(decode("a&NotEqualTilde;b&fjlig;c"), "a\u{2242}\u{338}bfjc");
        // The longest legacy name without `;`; others stay literal.
        assert_eq!(
            decode("&notit; &noti &eacutex &ccaron &ensp"),
            "¬it; ¬i éx &ccaron \u{2002}"
        );
        assert_eq!(decode("a&pi b&pi;"), "a&pi bπ");
    }

    #[test]
    fn every_dropped_marker_maps_to_its_source_range() {
        let source = "a⟦X⟧b ⟧c &#x27E6;Y&#x27E7;d ⟦e";
        let decoded = DecodedText::new(source);
        let markers: Vec<&str> = decoded
            .markers()
            .iter()
            .map(|&(start, end)| &source[start..end])
            .collect();
        assert_eq!(markers, ["⟦X⟧", "⟧", "&#x27E6;Y&#x27E7;", "⟦"]);
    }

    #[test]
    fn nesting_past_the_cap_fails_closed_on_the_whole_token() {
        let source = format!("check sk&{}#45;abc, please", "amp;".repeat(MAX_PASSES));
        let decoded = DecodedText::new(&source);
        // The token runs from whitespace to whitespace, its comma included.
        assert_eq!(decoded.unresolved(), [(6, source.len() - 7)]);
        // One layer less folds: nothing is unresolved.
        let source = format!("sk&{}#45;abc", "amp;".repeat(MAX_PASSES - 2));
        assert_eq!(DecodedText::new(&source).text(), "sk-abc");
        assert!(DecodedText::new(&source).unresolved().is_empty());
    }

    #[test]
    fn url_segments_split_on_url_separators() {
        let source = "see https://linkedin.example.invalid/in/jules-ferrand?name=ana%2Bmaria";
        let segments = DecodedText::url_segments(source);
        let values: Vec<&str> = segments
            .iter()
            .map(|(value, _, _)| value.as_str())
            .collect();
        assert!(values.contains(&"jules"));
        assert!(values.contains(&"ferrand"));
        assert!(values.contains(&"ana"));
        assert!(values.contains(&"maria"));
        for (value, start, end) in &segments {
            assert_eq!(&source[*start..*end], value.as_str());
        }
    }

    /// The decode pass must stay linear: the range lookup is a cursor, not a
    /// scan of every URL, and the entity scan is bounded before it looks for the
    /// terminator.
    ///
    /// Release on a Linux build server: 77 ms for the escape/URL case and 27 ms
    /// for the bare `&` case. Debug is about 7x slower, so the debug bound is
    /// 2 s.
    fn decode_budget() -> Duration {
        if cfg!(debug_assertions) {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(200)
        }
    }

    #[test]
    fn many_escapes_and_urls_decode_within_the_budget() {
        // 10 000 URLs, five percent escapes each. The old range lookup tested
        // every one of the 50 000 escapes against every URL.
        let url = "https://h.invalid/p?x=%41%42%43%44%45 ";
        let mut text = String::with_capacity(1_100_000);
        for _ in 0..10_000 {
            text.push_str(url);
        }
        while text.len() < 1_000_000 {
            text.push_str("padding ");
        }
        assert_eq!(text.matches('%').count(), 50_000);
        assert_eq!(text.matches("://").count(), 10_000);
        let start = Instant::now();
        let decoded = DecodedText::new(&text);
        let elapsed = start.elapsed();
        eprintln!(
            "decode {} bytes / 50 000 escapes / 10 000 URLs: {elapsed:?}",
            text.len()
        );
        assert!(decoded.text().contains("ABCDE"));
        assert!(
            elapsed < decode_budget(),
            "decode of {} bytes with 50 000 escapes took {elapsed:?}",
            text.len()
        );
    }

    /// 1 MiB of adversarial entity soup: deep `&amp;` nesting, long digit runs,
    /// markers and hidden characters. Every pass is linear and there are at
    /// most [`MAX_PASSES`] of them, so the bound is the same as for one pass
    /// times the cap: 10 s debug, 1 s release.
    #[test]
    fn adversarial_entity_soup_stays_linear() {
        let nested = "amp;".repeat(40);
        let piece = format!(
            "&{nested}#45;&#000000000000000045&EACUTE⟦PERSON_ABC⟧⟦\u{200B}&shy;&#x27E6;&am"
        );
        let text = piece.repeat((1 << 20) / piece.len() + 1);
        let start = Instant::now();
        let decoded = DecodedText::new(&text);
        let elapsed = start.elapsed();
        eprintln!("decode 1 MiB of entity soup: {elapsed:?}");
        assert!(!decoded.text().contains('⟦'));
        let bound = decode_budget() * 5;
        assert!(elapsed < bound, "1 MiB of entity soup took {elapsed:?}");
        // Openers with no `⟧` anywhere: each looks for its bracket once.
        let start = Instant::now();
        assert_eq!(
            DecodedText::new(&"⟦a".repeat(1 << 18)).text().len(),
            1 << 18
        );
        assert!(
            start.elapsed() < bound,
            "1 MiB of openers took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn an_ampersand_with_no_semicolon_stays_bounded() {
        let text = "&".repeat(1_000_000);
        let start = Instant::now();
        let decoded = DecodedText::new(&text);
        let elapsed = start.elapsed();
        eprintln!("decode 1 MB of bare `&`: {elapsed:?}",);
        assert_eq!(decoded.text().len(), text.len());
        assert!(
            elapsed < decode_budget(),
            "decode of 1 MB of bare `&` took {elapsed:?}"
        );
    }
}
