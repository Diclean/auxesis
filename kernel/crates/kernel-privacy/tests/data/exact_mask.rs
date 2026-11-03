// Exact mask alignment: the byte ranges a gate output **really** masks, read one
// way only. Shared by every superset and differential test in this crate.
//
// The older reader split an output into clear pieces and dropped each piece at
// the *first* place it appeared in the input, so it passed a text it could not
// align at all: with two masks side by side, one clear piece landed inside the
// first mask and a value that really sat in the clear came back "masked". The
// gate output is not ambiguous — every token stands for a value the gate minted,
// and every `[<class> removed]` marker stands for the range the Open detector
// removed — so this reader uses that, and no second reading is left to fall back
// on:
//
// * Private: each `⟦NAME⟧` stands for the surface the gate minted for `NAME`
//   (`Gate::take_minted`), so the output walks the input from byte 0: a token
//   must cover its own surface at the cursor, and every clear character must be
//   the input's character at the cursor. A `⟦⟦` in the output is the gate's
//   escaping of one literal `⟦` of the input, which it leaves clear, and a
//   token the gate minted nothing for is the input's own literal text, which it
//   keeps as it is. A token may also stand for a *piece* of one detector span,
//   the way the gate's residue round writes several tokens for one span it
//   cannot mask whole; the pieces come from the same detector's residue view,
//   so each one is a value read at its own place (TEST-FITS-EXACT-2).
// * Open: the removed ranges are the prohibited spans of `StandardDetector`,
//   the detector the Open gate of `Gate::for_grant` runs, plus the export
//   columns the gate hides on top of it, and the output must be exactly the clear text between them with one `[<class> removed]` marker
//   in place of each.
//
// Nothing here is matched by shape. A token the gate minted nothing for is the
// input's own literal text, a marker is one of the five fixed removal strings
// `safetext.rs` writes, and a token takes a detector span only when the gate
// minted that name: a `⟦HEALTH_4412⟧` no gate ever minted is a token name that
// spells a value, and `[health 4412 removed]` is a marker that spells one.
//
// `None` from [`exact_ranges`] means the output does not read back onto the
// input at all. A caller must treat that as a failure, never as "some reading
// of the output kept the value hidden": TEST-FITS-EXACT.

/// The ranges of `input` the gate output in `mode` masked, or `None` when the
/// output does not read back onto `input` exactly.
///
/// `minted` is what the gate reported for this text (`Gate::take_minted`); only
/// the Private path reads it.
pub fn exact_ranges(
    mode: kernel_core::privacy::PrivacyMode,
    input: &str,
    output: &str,
    minted: &[(String, String)],
) -> Option<Vec<(usize, usize)>> {
    match mode {
        kernel_core::privacy::PrivacyMode::Private => private_ranges(input, output, minted),
        _ => open_ranges(input, output),
    }
}

/// [`exact_ranges`], or a panic: a text that does not align exactly fails, never
/// passes. The message carries the input and the output, which is the whole
/// evidence a leak report needs.
pub fn exact_or_fail(
    mode: kernel_core::privacy::PrivacyMode,
    input: &str,
    output: &str,
    minted: &[(String, String)],
) -> Vec<(usize, usize)> {
    exact_ranges(mode, input, output, minted).unwrap_or_else(|| {
        panic!("{mode:?} output does not align exactly: {input:?} -> {output:?}")
    })
}

/// The ranges a Private output masks, or `None`.
///
/// One pass over the output, from byte 0 of both sides: a token covers its own
/// surface at the cursor, a clear character is the input's character at the
/// cursor, and the input must be used up exactly.
fn private_ranges(
    input: &str,
    output: &str,
    minted: &[(String, String)],
) -> Option<Vec<(usize, usize)>> {
    let mut spans = None;
    let (mut out, mut at, mut rest) = (Vec::new(), 0, output);
    while let Some(ch) = rest.chars().next() {
        // The gate doubles a literal `⟦` in the text it leaves clear
        // (`Anonymizer::push_escaped`), so `⟦⟦` stands for one input `⟦` and
        // for nothing else: a minted name is `KIND_HEX`, so a name holding a
        // `⟦` is not one. Reading it as a token name instead is how an escaped
        // marker text came back as "no exact reading" at all.
        if rest.starts_with("\u{27E6}\u{27E6}") {
            input[at..].starts_with('\u{27E6}').then_some(())?;
            at += '\u{27E6}'.len_utf8();
            rest = &rest[2 * '\u{27E6}'.len_utf8()..];
            continue;
        }
        if let Some(body) = rest.strip_prefix('\u{27E6}') {
            let name = &body[..body.find('\u{27E7}')?];
            let (covered, token) = cover_token(input, at, name, minted, &mut spans, &mut out)?;
            at += covered;
            rest = &rest[token..];
            continue;
        }
        input[at..].starts_with(ch).then_some(())?;
        at += ch.len_utf8();
        rest = &rest[ch.len_utf8()..];
    }
    (at == input.len()).then(|| merge(out.iter().copied()))
}

/// The two views of the input the gate reads, computed at most once each per
/// output and only once a token has reached them. Both come from the one
/// detector: `Detector::detect` is the gate's first round, `Detector::residue`
/// its second.
#[derive(Default)]
struct Views {
    read: Option<Vec<Span>>,
    pieces: Option<Vec<Span>>,
}

/// A detector span: its class and its byte range.
type Span = (kernel_privacy::EntityKind, usize, usize);

/// The bytes a `⟦name⟧` at the cursor of `input` covers, pushing that range, or
/// `None` when nothing can stand there. The pair is the input bytes the token
/// hides and the output bytes the token takes.
///
/// Four sources, in order, and none of them is a reading:
///
/// 1. the surface the gate minted for `name`, when it sits at the cursor — one
///    name stands for one value, so this is the gate's own restore;
/// 2. the detector's own span of the token's class, when exactly one starts at
///    the cursor **and the gate minted that name**. A token covers several
///    spellings of one value and `take_minted` keeps only the first, so this is
///    the case where the minted surface is another spelling of the value at
///    hand — or a token a previous call of the same gate minted, which is why
///    the name is looked up in the whole `minted` list and not only in this
///    call's. Without the minted test any `⟦<CLASS>_…⟧` would stand for a
///    detector span, including a name that spells the value it hides
///    (`⟦HEALTH_4412⟧`), which the gate never mints. The gate masks whole
///    regions (a region over that kind's [`span_cap`] is split first), so a
///    token covers a whole span of its class and nothing less;
/// 3. the token as literal text, which is what the gate does with a token-shaped
///    string it minted nothing for;
/// 4. the gate's own **piece** of one span of the class: the residue view's
///    span, when exactly one of its class starts at the cursor, it fits the
///    class cap, and the reading view holds it inside a span of that class.
///    The gate's residue round masks a first-round span that is not one whole
///    maskable value piece by piece, and writes one token per piece under the
///    name `take_minted` recorded for the first of them, so a piece is the only
///    thing a later token of a split span can stand for. Without this source a
///    text with two spellings of one number in one span had **no** exact
///    reading at all: a false red, never a false green (TEST-FITS-EXACT-2).
///
/// Source 4 comes after source 3 on purpose: it may only read a text that
/// nothing else reads, so every output that read back before still reads back
/// the same way and a frozen baseline cannot move.
fn cover_token(
    input: &str,
    at: usize,
    name: &str,
    minted: &[(String, String)],
    spans: &mut Option<Views>,
    out: &mut Vec<(usize, usize)>,
) -> Option<(usize, usize)> {
    let token = '\u{27E6}'.len_utf8() + name.len() + '\u{27E7}'.len_utf8();
    let minted_name = minted.iter().any(|(token, _)| token == name);
    if let Some(surface) = minted
        .iter()
        .filter(|(token, _)| *token == name)
        .map(|(_, surface)| surface.as_str())
        .filter(|surface| input[at..].starts_with(surface))
        .max_by_key(|surface| surface.len())
    {
        out.push((at, at + surface.len()));
        return Some((surface.len(), token));
    }
    let class = kernel_privacy::EntityKind::parse(name.rsplit_once('_').map_or(name, |(k, _)| k))
        .filter(|_| minted_name);
    // Sources 2 and 4 need a class this gate minted a name for; source 3 does
    // not, so the literal text is read between them.
    if let Some(class) = class {
        let cap = span_cap(class);
        let views = spans.get_or_insert_with(Views::default);
        let read = views
            .read
            .get_or_insert_with(|| detector::read(input).unwrap_or_default());
        if let Some(end) = whole_span(read, class, at, cap) {
            out.push((at, end));
            return Some((end - at, token));
        }
    }
    if input[at..].starts_with(&format!("\u{27E6}{name}\u{27E7}")) {
        return Some((token, token));
    }
    let class = class?;
    let cap = span_cap(class);
    let views = spans.get_or_insert_with(Views::default);
    let read = views
        .read
        .get_or_insert_with(|| detector::read(input).unwrap_or_default());
    let pieces = views
        .pieces
        .get_or_insert_with(|| detector::pieces(input).unwrap_or_default());
    whole_span(pieces, class, at, cap)
        .filter(|&end| {
            read.iter()
                .any(|&(k, s, e)| k == class && s <= at && end <= e)
        })
        .map(|end| {
            out.push((at, end));
            (end - at, token)
        })
}

/// The end of the one span of `kind` that starts at `at` and fits the cap, or
/// `None`: a token stands for one whole value, so two spans that end differently
/// there are not a reading, they are a refusal.
fn whole_span(
    spans: &[Span],
    kind: kernel_privacy::EntityKind,
    at: usize,
    cap: usize,
) -> Option<usize> {
    let mut ends: Vec<usize> = spans
        .iter()
        .filter(|(k, start, _)| *k == kind && *start == at)
        .map(|&(_, _, end)| end)
        .filter(|&end| end - at <= cap)
        .collect();
    ends.sort_unstable();
    ends.dedup();
    match ends.as_slice() {
        [end] => Some(*end),
        _ => None,
    }
}

/// The longest span of `kind` the detector returns whole, which is the longest a
/// token of that class can cover: `split_long_spans` keeps a secret as one span
/// up to [`MAX_KEY_SPAN_BYTES`] and splits every other kind at
/// [`MAX_SPAN_BYTES`]. Filtering a candidate on the smaller of the two would
/// drop a secret of 129–512 bytes, which the gate mints as one token.
fn span_cap(kind: kernel_privacy::EntityKind) -> usize {
    if kind == kernel_privacy::EntityKind::Secret {
        kernel_privacy::recognizer::MAX_KEY_SPAN_BYTES
    } else {
        kernel_privacy::recognizer::MAX_SPAN_BYTES
    }
}

/// The ranges an Open output removes, or `None`.
///
/// The removed ranges are the detector's own: `Gate::for_grant` runs
/// `StandardDetector` in Open mode, and each maximal merged prohibited range
/// becomes exactly one marker, so the output must read back as the clear text
/// between those ranges with a marker in place of each.
///
/// A marker is the one fixed string `remove_prohibited` writes for that range's
/// class — one of seven, compared whole. Matching a shape instead would let
/// `[health 4412 removed]` stand for a health span, so the value would read as
/// removed while it sits in the output, and it would let `[iban removed]` stand
/// for a health span, which is not a marker the gate can write at all.
fn open_ranges(input: &str, output: &str) -> Option<Vec<(usize, usize)>> {
    let mut spans: Vec<(usize, usize, kernel_privacy::EntityKind)> = detector::prohibited(input)?
        .into_iter()
        .map(|(kind, start, end)| (start, end, kind))
        .collect();
    // The export columns the gate hides on top of the detector (SECRET-LEAK-294B).
    let export = kernel_privacy::safetext::export_column_ranges(input);
    spans.extend(
        export
            .into_iter()
            .map(|(start, end)| (start, end, kernel_privacy::EntityKind::Secret)),
    );
    spans.sort_unstable();
    let found = merge_prohibited(spans);
    let (mut at, mut rest) = (0, output);
    for &(start, end, kind) in &found {
        rest = rest.strip_prefix(&input[at..start])?;
        rest = rest.strip_prefix(removal_marker(kind)?)?;
        at = end;
    }
    (rest == &input[at..]).then(|| found.into_iter().map(|(s, e, _)| (s, e)).collect())
}

/// The exact text a passthrough gate writes in place of a span of `kind`: the
/// seven fixed markers of `safetext.rs::removal_text`, and `None` for a kind
/// Open mode leaves in clear.
fn removal_marker(kind: kernel_privacy::EntityKind) -> Option<&'static str> {
    use kernel_privacy::EntityKind as Kind;
    Some(match kind {
        Kind::Secret => "[secret removed]",
        Kind::Iban => "[iban removed]",
        Kind::CreditCard => "[card removed]",
        Kind::Health => "[health removed]",
        Kind::Address => "[address removed]",
        Kind::DateOfBirth => "[date of birth removed]",
        Kind::FrNir
        | Kind::HuTaj
        | Kind::HuTaxId
        | Kind::ZaId
        | Kind::UkNino
        | Kind::PassportMrz
        | Kind::NationalId => "[id removed]",
        _ => return None,
    })
}

/// Touching prohibited ranges as one, each with the class its merged range
/// takes: `remove_prohibited` merges the same way (`start <= last end`) and
/// gives a merged range the marker of its highest-priority kind.
fn merge_prohibited(
    ranges: Vec<(usize, usize, kernel_privacy::EntityKind)>,
) -> Vec<(usize, usize, kernel_privacy::EntityKind)> {
    let mut out: Vec<(usize, usize, kernel_privacy::EntityKind)> = Vec::new();
    for (start, end, kind) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1 => {
                last.1 = last.1.max(end);
                if kind.mask_priority() < last.2.mask_priority() {
                    last.2 = kind;
                }
            }
            _ => out.push((start, end, kind)),
        }
    }
    out
}

/// The detector the gate runs, behind its own `use` so this file can sit in a
/// module that imports the same names itself.
mod detector {
    use super::Span;
    use kernel_privacy::safetext::Detector;

    /// Every span `StandardDetector` finds in `text`: the gate's own first
    /// round, the regions it masks whole.
    pub fn read(text: &str) -> Option<Vec<Span>> {
        kernel_privacy::StandardDetector::new()
            .detect(text)
            .ok()
            .map(plain)
    }

    /// The spans of [`read`] that never leave the Mac
    /// (`kernel_privacy::Span::is_prohibited`): a prohibited kind, or a date of
    /// birth after its label.
    pub fn prohibited(text: &str) -> Option<Vec<Span>> {
        kernel_privacy::StandardDetector::new()
            .detect(text)
            .ok()
            .map(|spans| spans.into_iter().filter(|s| s.is_prohibited()).collect())
            .map(plain)
    }

    /// The same detector on its residue view (`Registry::analyze_values`), whose
    /// spans are the values it reads without the context of the text around
    /// them. These are the pieces `Gate::apply_spans` masks, one token each,
    /// when a first-round span is not one whole maskable value — the case the
    /// NINO-NEWLINE-SUFFIX corpus turns up, where one number spelled twice
    /// inside one span becomes two tokens under one name.
    pub fn pieces(text: &str) -> Option<Vec<Span>> {
        kernel_privacy::StandardDetector::new()
            .residue(text)
            .ok()
            .map(plain)
    }

    fn plain(spans: Vec<kernel_privacy::Span>) -> Vec<Span> {
        spans
            .into_iter()
            .map(|span| (span.kind, span.start, span.end))
            .collect()
    }
}

/// Touching ranges as one: two masks side by side cover one run of bytes.
fn merge(ranges: impl Iterator<Item = (usize, usize)>) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}
