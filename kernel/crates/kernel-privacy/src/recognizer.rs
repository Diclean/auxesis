//! The [`Recognizer`] trait and the [`Registry`] that runs a set of them.
//!
//! The registry is the deterministic half of the Presidio architecture: it
//! runs every enabled recogniser, validates each span against the original
//! UTF-8 text, applies the context enhancer, applies per-kind thresholds, and
//! resolves overlaps.

use std::cell::Cell;
use std::sync::Arc;

use crate::anonymize::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use crate::contacts::fold::is_default_ignorable;
use crate::context::ContextEnhancer;
use crate::decode::{self, DecodedText};
use crate::email_layer::EmailLayer;
use crate::normalize::{NormalizedText, SharedViews};
use crate::recognizers;
use crate::span::{EntityKind, Span};
use crate::threshold::Thresholds;

/// Confidence given to a span from a recogniser whose rule is not verified.
///
/// Lower than a verified hit (`1.0`) but still above the generic floor: an
/// unverified rule still masks, it just labels the span `NATIONAL_ID`.
pub const UNVERIFIED_SCORE: f32 = 0.6;

/// Confidence for a checksum-valid value with no cue and no verified rule.
///
/// The registry never drops such a value: it relabels it `NATIONAL_ID` at this
/// score, so masking fails toward masking (maintainer policy for this masker).
pub const GENERIC_FALLBACK_SCORE: f32 = 0.6;

/// Longest span, in bytes: a longer detection is split into pieces at or below
/// this length (on character boundaries) instead of masking a huge region.
pub const MAX_SPAN_BYTES: usize = 128;

/// Longest API key kept as one token, in bytes. A provider key is one secret
/// and a wrapped one runs well past [`MAX_SPAN_BYTES`]; a key longer than this
/// still splits, so a token stays bounded.
pub const MAX_KEY_SPAN_BYTES: usize = 512;

/// Rounds of decode and fold the registry composes (NORM-2). A fold creates
/// escapes of its own (`＆` folds to `&`, so `&#105;` reads only after a second
/// decode) and what that escape reads folds again. Real mail nests one or two
/// layers; the cap keeps adversarial nesting a fixed number of linear passes.
const COMPOSITION_ROUNDS: usize = 3;

/// A deterministic detector for one or more [`EntityKind`]s.
pub trait Recognizer: Send + Sync {
    /// The kinds this recogniser can emit.
    fn kinds(&self) -> &[EntityKind];

    /// Find every value of the declared kinds in `text`.
    fn analyze(&self, text: &str) -> Vec<Span>;

    /// Find values in a transformed view while retaining its mapping to the
    /// original input. Recognisers that use source token boundaries can
    /// override this; other recognisers keep their existing view-only scan.
    fn analyze_with_source(
        &self,
        text: &str,
        _original: &str,
        _source_bounds: &dyn Fn(usize, usize) -> Option<(usize, usize)>,
    ) -> Vec<Span> {
        self.analyze(text)
    }

    /// A short stable name, echoed in [`Span::recognizer`].
    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    /// Whether the rule has been checked against an official source.
    fn verified(&self) -> bool {
        true
    }

    /// Whether the default registry mounts this recogniser.
    ///
    /// Since the masker must fail toward masking, an unverified rule is still
    /// mounted: `verified` only controls the score and the label
    /// ([`UNVERIFIED_SCORE`]), never whether a checksum-valid value is masked.
    fn enabled_by_default(&self) -> bool {
        true
    }
}

/// A set of recognisers plus the context enhancer and thresholds they run
/// under.
pub struct Registry {
    recognizers: Vec<Box<dyn Recognizer>>,
    context: ContextEnhancer,
    thresholds: Thresholds,
    /// The email-aware post-pass of slice 1e. `None` reproduces the pre-1e
    /// behaviour exactly, which the eval harness uses as its "before" arm.
    email_layer: Option<EmailLayer>,
    /// Whether person and organisation spans reach the overlap merge. A private
    /// gate turns this off (NAMES-OFF): a name dropped only after the merge
    /// would take the hard value it overlapped with it.
    keep_names: bool,
}

impl Registry {
    /// The default registry: every recogniser, default context and thresholds,
    /// and the email-aware layer (slice 1e).
    ///
    /// The unverified rules (NIR, SIRET, passport MRZ) are mounted too: their
    /// spans are relabelled `NATIONAL_ID` at a lower score, never dropped.
    pub fn new() -> Self {
        Self {
            recognizers: recognizers::default_recognizers(),
            context: ContextEnhancer::new(),
            thresholds: Thresholds::new(),
            email_layer: Some(EmailLayer::new()),
            keep_names: true,
        }
    }

    /// This registry without its person and organisation spans. They are
    /// dropped before the overlap merge, so every other span merges and masks
    /// on its own: a name can never widen over, relabel or remove a hard value.
    /// Public so the eval scores what private mode really masks.
    pub fn without_names(mut self) -> Self {
        self.keep_names = false;
        self
    }

    /// A builder for a custom registry.
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder {
            recognizers: Vec::new(),
            context: ContextEnhancer::new(),
            thresholds: Thresholds::new(),
            email_layer: Some(EmailLayer::new()),
        }
    }

    /// The mounted recognisers, in run order.
    pub fn recognizers(&self) -> &[Box<dyn Recognizer>] {
        &self.recognizers
    }

    /// The thresholds in force.
    pub fn thresholds(&self) -> &Thresholds {
        &self.thresholds
    }

    /// The email-aware layer, when mounted.
    pub fn email_layer(&self) -> Option<&EmailLayer> {
        self.email_layer.as_ref()
    }

    /// Run every recogniser and return the surviving spans, ordered by start
    /// offset. Overlapping or adjacent spans of every kind are merged into the
    /// exact union of the bytes a caller must mask, so the returned regions are
    /// non-overlapping and cover every detected byte once. A `PERSON` span that
    /// overlaps an email, URL or phone region takes that region's
    /// highest-priority kind; a name alone keeps its `PERSON` kind.
    ///
    /// The pipeline fails toward masking:
    ///
    /// * a span from an unverified recogniser is relabelled `NATIONAL_ID` at
    ///   [`UNVERIFIED_SCORE`], so it is masked without claiming a specific rule;
    /// * a checksum-valid span whose score stays below its kind's floor (no cue)
    ///   is relabelled `NATIONAL_ID` at [`GENERIC_FALLBACK_SCORE`] rather than
    ///   dropped;
    /// * every surviving span longer than [`MAX_SPAN_BYTES`] is split.
    ///
    /// When the email-aware layer is mounted, every `PERSON` span any recogniser
    /// produced — including one below its floor — seeds name propagation, and
    /// the layer adds its own decoded, greeting, company-id and tracking spans
    /// before the overlap resolution.
    pub fn analyze(&self, text: &str) -> Vec<Span> {
        let mut spans = self.analyze_tagged(text);
        spans.retain(|span| span.recognizer != NAME_WIDENED);
        spans
    }

    /// [`Registry::analyze`], plus, for a registry without names, each
    /// [`NAME_WIDENED`] region after the merged ones (it overlaps them).
    pub(crate) fn analyze_tagged(&self, text: &str) -> Vec<Span> {
        let layer = self.email_layer.as_ref();
        let glyph = Cell::new(false);
        let main = self.analyze_with(text, layer, Folds::Main, &glyph);
        if !glyph.get() {
            return main;
        }
        // NORM-GLYPH: some view held a full-width `＆`, `＃` or `％`, so the glyph
        // folds may read an escape the main folds leave alone. The whole pipeline
        // runs again on those folds, and the masks are the union of both runs:
        // every main region stays covered, with its prohibited kind
        // ([`resolve_overlaps`]), so the extra run can only add masks.
        let extra = self.analyze_with(text, layer, Folds::Glyph, &glyph);
        let (widened, spans): (Vec<Span>, Vec<Span>) = main
            .into_iter()
            .chain(extra)
            .partition(|span| span.recognizer == NAME_WIDENED);
        let mut regions = split_long_spans(text, resolve_overlaps(spans));
        regions.extend(widened);
        regions
    }

    /// The deterministic recognisers only: the same pipeline with no e-mail
    /// layer, so no name heuristic runs. The gate's residue scan reads text
    /// through this view, because the layer's name cues depend on the words
    /// around a value, and masking changes those words.
    ///
    /// It reads the main folds only, never the NORM-GLYPH ones: a refusal comes
    /// from this scan, so what refuses is exactly what refused before the extra
    /// views existed.
    pub fn analyze_values(&self, text: &str) -> Vec<Span> {
        let mut spans = self.analyze_with(text, None, Folds::Main, &Cell::new(false));
        spans.retain(|span| span.recognizer != NAME_WIDENED);
        spans
    }

    /// Run every recogniser over `view`. For a decoded or folded view, `mapped`
    /// holds its map back and the original text: a span is mapped back before
    /// it is kept.
    fn scan(
        &self,
        view: &str,
        mapped: Option<(&SourceBounds<'_>, &str)>,
        candidates: &mut Vec<Span>,
        seeds: &mut Vec<Span>,
    ) {
        let _views = SharedViews::new(view);
        for recognizer in &self.recognizers {
            let verified = recognizer.verified();
            let found = match mapped {
                Some((source_bounds, original)) => {
                    recognizer.analyze_with_source(view, original, source_bounds)
                }
                None => recognizer.analyze(view),
            };
            for mut span in found {
                if !span_is_well_formed(view, &span) {
                    continue;
                }
                if !verified {
                    span.kind = EntityKind::NationalId;
                    span.score = span.score.min(UNVERIFIED_SCORE);
                }
                self.context.enhance(view, &mut span);
                if let Some((source_bounds, original)) = mapped {
                    let Some((start, end)) = source_bounds(span.start, span.end) else {
                        continue;
                    };
                    span.start = start;
                    span.end = end;
                    if !span_is_well_formed(original, &span) {
                        continue;
                    }
                }
                if span.kind == EntityKind::Person {
                    seeds.push(span);
                }
                if span.score >= self.thresholds.get(span.kind) {
                    candidates.push(span);
                    continue;
                }
                if span.kind == EntityKind::NationalId {
                    continue;
                }
                let mut generic = span;
                generic.kind = EntityKind::NationalId;
                generic.score = GENERIC_FALLBACK_SCORE;
                if generic.score >= self.thresholds.get(EntityKind::NationalId) {
                    candidates.push(generic);
                }
            }
        }
    }

    /// The pipeline over one set of folds. `glyph` is set when a text it folds
    /// holds a character the glyph folds may read another way.
    fn analyze_with(
        &self,
        text: &str,
        layer: Option<&EmailLayer>,
        folds: Folds,
        glyph: &Cell<bool>,
    ) -> Vec<Span> {
        let folded_views = |view: &str| folds.views(view, glyph);
        let mut candidates: Vec<Span> = Vec::new();
        let mut seeds: Vec<Span> = Vec::new();
        self.scan(text, None, &mut candidates, &mut seeds);
        // A value written with HTML entities (`chimioth&eacute;rapie`,
        // `sk&#45;key`) is invisible to a recogniser on the raw bytes. The
        // recognisers read the decoded view too, and a span maps back to every
        // source byte of the value, so masking never depends on a name rule.
        // A text decoding leaves alone has no marker and no decoded view: do
        // not build one (every ASCII text without `&` or `%`).
        let decoded = (!DecodedText::is_unchanged(text)).then(|| DecodedText::new(text));
        let runs: Vec<(usize, usize)> = decoded
            .as_ref()
            .map_or_else(Vec::new, |view| marker_runs(text, view.markers()));
        let mut views: Vec<DecodedText> = decoded.into_iter().collect();
        if views.first().is_some_and(DecodedText::dropped_marker_body) {
            // A value inside a `⟦…⟧` pair: read it with only the brackets gone.
            views.push(DecodedText::brackets_only(text));
        }
        // Every marked text is also read with each bracket as a space, so a
        // value a bracket touches keeps its boundary (`texte⟦sk-…⟧`,
        // `1⟦sk-…⟧`). A test on the dropped view's markers is not enough: a
        // nested or unbalanced bracket (`⟦1⟦sk-…⟧ ⟧`) hides inside the outer
        // pair that view drops whole.
        if views.first().is_some_and(|view| !view.markers().is_empty()) {
            views.push(DecodedText::brackets_as_spaces(text));
        }
        // A marker between two letters splices a word (`chimioth⟦X⟧éra⟦pie ⟧`):
        // its run fails closed. Maths and markdown put markers at word edges.
        let spliced = views.iter().filter(|view| view.mode_drops_brackets());
        for view in spliced {
            for &marker in view.markers() {
                if view.marker_joins_letters(marker) {
                    let at = runs.partition_point(|run| run.1 <= marker.0);
                    if let Some(&(start, end)) = runs.get(at) {
                        candidates.push(Span::new(EntityKind::Secret, start, end, 1.0, MARKER_RUN));
                    }
                }
            }
        }
        // NORM-1 and NORM-2: every decoded view, every fold of one and every
        // fold of the raw text are the first round of the composition below.
        let mut frontier: Vec<Chain> = Vec::new();
        for view in views.into_iter().filter(|view| view.text() != text) {
            let decoded = Arc::new(view);
            let chain = [Step::Decoded(Arc::clone(&decoded))];
            self.scan_chain(&chain, text, &mut candidates, &mut seeds);
            // Still encoded at the pass cap: the whole token is masked.
            for &(start, end) in decoded.unresolved() {
                candidates.push(Span::new(EntityKind::Secret, start, end, 1.0, "decode-cap"));
            }
            // A look-alike behind an entity (`di&#1072;betes`): the decoded view
            // is folded too, and a span maps back through both maps. Each view
            // is the first round of a [`Chain`] the composition extends.
            for folded in folded_views(decoded.text()) {
                let mut folded_chain = chain.to_vec();
                folded_chain.push(Step::Folded(folded));
                self.scan_chain(&folded_chain, text, &mut candidates, &mut seeds);
                frontier.push(folded_chain);
            }
            frontier.push(chain.to_vec());
        }
        // NORM-1: look-alike, full-width, mathematical and invisible characters
        // read as the ASCII they stand for, and a span maps back to every byte.
        for view in folded_views(text) {
            let chain = vec![Step::Folded(view)];
            self.scan_chain(&chain, text, &mut candidates, &mut seeds);
            frontier.push(chain);
        }
        // NORM-2: decoding and folding compose.
        self.compose(
            &mut frontier,
            text,
            &folded_views,
            &mut candidates,
            &mut seeds,
        );
        if let Some(layer) = layer {
            candidates = layer.apply(text, candidates, &seeds);
        }
        // Append the new decoded views after the original pipeline, so they
        // cannot displace a mask selected by the existing e-mail layer.
        let escaped = text
            .match_indices(['\\', '%', '&'])
            .any(|(at, _)| decode::known_escape_at(text, at, &|_, _| None))
            .then(|| DecodedText::escaped(text, false))
            .flatten();
        if let Some(escaped) = escaped {
            let brackets = escaped
                .dropped_marker_body()
                .then(|| DecodedText::escaped(text, true))
                .flatten();
            for view in std::iter::once(escaped).chain(brackets) {
                for &(start, end) in view.unresolved() {
                    candidates.push(Span::new(EntityKind::Secret, start, end, 1.0, "escape-cap"));
                }
                if view.text() != text {
                    let chain = vec![Step::Decoded(Arc::new(view))];
                    self.scan_chain(&chain, text, &mut candidates, &mut seeds);
                    for folded in folded_views(chain_text(&chain)) {
                        let mut next = chain.clone();
                        next.push(Step::Folded(folded));
                        self.scan_chain(&next, text, &mut candidates, &mut seeds);
                    }
                }
            }
        }
        // A value that touches a marker's run takes the whole run: dropping the
        // marker may have joined or split it. A run no view finds a value in
        // stays text (`⟦x + 1⟧`). A gate that keeps the session's own tokens
        // blanks them before detection, so they are never runs.
        widen_over_runs(&mut candidates, &runs);
        let regions = |spans: Vec<Span>| {
            let expanded = expand_person_spans(text, extend_hyphenated_persons(text, spans));
            split_long_spans(text, resolve_overlaps(expanded))
        };
        if self.keep_names {
            return regions(candidates);
        }
        // A name never masks on its own here, but the registry with names, and
        // Open mode, hide every byte the merge with names gave a prohibited
        // region. Such a region is appended, tagged [`NAME_WIDENED`], when it
        // reads a letter or digit the regions without names leave clear; the
        // gate masks it after its main rounds (GATE-REGISTRY-GAP-1).
        let named = regions(candidates.clone());
        candidates
            .retain(|span| !matches!(span.kind, EntityKind::Person | EntityKind::Organization));
        let mut plain = regions(candidates);
        let widened: Vec<Span> = named
            .into_iter()
            .filter(|region| region.is_prohibited() && adds_readable(text, region, &plain))
            .map(|region| Span {
                recognizer: NAME_WIDENED,
                ..region
            })
            .collect();
        plain.extend(widened);
        plain
    }

    /// Scan a composed view: the text its last step reads, and its map back to
    /// `original` through every step of the chain.
    fn scan_chain(
        &self,
        chain: &[Step],
        original: &str,
        candidates: &mut Vec<Span>,
        seeds: &mut Vec<Span>,
    ) {
        let bounds = |start, end| chain_bounds(chain, start, end);
        self.scan(
            chain_text(chain),
            Some((&bounds, original)),
            candidates,
            seeds,
        );
    }

    /// NORM-2: decoding and folding compose, because a fold creates escapes of
    /// its own — `&#65286;` decodes to `＆`, whose fold supplies the `&` of
    /// `&#105;`, which a second decode reads as the `i` of `sk-proj`, and that
    /// folds again (`о` reads as `o`).
    ///
    /// Every chain of `frontier` is decoded again and each fold of it is scanned
    /// too, [`COMPOSITION_ROUNDS`] rounds deep; a chain keeps the map of every
    /// step, so a span still covers all of the source bytes of its value. Never
    /// recursive, always linear: a fixed number of rounds of linear passes.
    fn compose(
        &self,
        frontier: &mut Vec<Chain>,
        text: &str,
        folded_views: &dyn Fn(&str) -> Vec<NormalizedText>,
        candidates: &mut Vec<Span>,
        seeds: &mut Vec<Span>,
    ) {
        for _ in 1..COMPOSITION_ROUNDS {
            let mut next: Vec<Chain> = Vec::new();
            for chain in frontier.iter() {
                let view = chain_text(chain);
                // Nothing left to decode: an entity needs `&`, a percent escape
                // `%`, and every marker or invisible character is outside ASCII.
                if view.is_ascii() && !view.contains(['&', '%']) {
                    continue;
                }
                let decoded = Arc::new(DecodedText::brackets_only(view));
                if decoded.text() == view {
                    continue;
                }
                let mut decoded_chain = chain.clone();
                decoded_chain.push(Step::Decoded(Arc::clone(&decoded)));
                // A marker this round decoded that the view spells no bracket is
                // a bracket an escape produced, and an escape a fold created is
                // one no real token spells: a token marker is written plainly.
                // Whatever the round did with the body behind it, the token
                // around it is masked whole.
                for &marker in decoded.markers() {
                    if is_bracket(view.get(marker.0..marker.1).unwrap_or_default()) {
                        continue;
                    }
                    let Some(bounds) = chain_bounds(&decoded_chain, marker.0, marker.1) else {
                        continue;
                    };
                    let (from, to) = token_around(text, bounds.0, bounds.1);
                    candidates.push(Span::new(
                        EntityKind::Secret,
                        from,
                        to,
                        1.0,
                        "compose-marker",
                    ));
                }
                // The decoded view, then each fold of it. A view that already
                // reads as ASCII folds to itself, so on its own the decoded view
                // is what this round adds.
                let folds = folded_views(decoded.text());
                if folds.is_empty() {
                    next.push(decoded_chain.clone());
                }
                for folded in folds {
                    let mut chain = decoded_chain.clone();
                    chain.push(Step::Folded(folded));
                    next.push(chain);
                }
            }
            for chain in &next {
                self.scan_chain(chain, text, candidates, seeds);
            }
            // Converged: no view of the last round decodes to something else.
            if next.is_empty() {
                *frontier = next;
                return;
            }
            *frontier = next;
        }
        // The cap is reached with work left. Fail closed: a spelling this deep
        // is not a real one, so every source region a further pass would still
        // change stays masked rather than read as clear.
        for chain in frontier.iter() {
            for (start, end) in still_encoded(chain) {
                candidates.push(Span::new(
                    EntityKind::Secret,
                    start,
                    end,
                    1.0,
                    "compose-cap",
                ));
            }
        }
    }
}

/// Which folds a pipeline run reads (NORM-GLYPH).
#[derive(Clone, Copy)]
enum Folds {
    /// [`NormalizedText::folded_views`]: the views every scan reads.
    Main,
    /// [`NormalizedText::glyph_views`]: the extra views, unioned with the main ones.
    Glyph,
}

impl Folds {
    /// The views of `text` this run scans. A main run marks `glyph` when the
    /// glyph folds may read `text` another way, so the extra run is needed.
    fn views(self, text: &str, glyph: &Cell<bool>) -> Vec<NormalizedText> {
        match self {
            Self::Main => {
                if NormalizedText::may_glyph_fold(text) {
                    glyph.set(true);
                }
                NormalizedText::folded_views(text)
            }
            Self::Glyph => NormalizedText::glyph_views(text),
        }
    }
}

/// A chain of decoded and folded views, from the source text to the view the
/// registry scans. Each step keeps its own map back to the step before it, so
/// composing the chain gives the map back to the source bytes.
type Chain = Vec<Step>;

/// One step of a [`Chain`]: a decoded or folded view of the previous step's
/// text.
#[derive(Clone)]
enum Step {
    Decoded(Arc<DecodedText>),
    Folded(NormalizedText),
}

impl Step {
    /// The text this step reads.
    fn text(&self) -> &str {
        match self {
            Self::Decoded(view) => view.text(),
            Self::Folded(view) => view.text(),
        }
    }

    /// A byte range of this step's text, as a range of the previous step's, or
    /// `None` when it is empty, out of bounds or off a char boundary.
    fn to_previous(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        match self {
            Self::Decoded(view) => view.source_bounds(start, end),
            Self::Folded(view) => view.to_original(start, end),
        }
    }
}

/// The text a chain reads: the text of its last step.
fn chain_text(chain: &[Step]) -> &str {
    chain.last().expect("a chain has a step").text()
}

/// A byte range of a chain's text as a range of the source bytes, through every
/// step of the chain. Each step only widens a range, so the result still
/// covers every original byte of the value inside it.
fn chain_bounds(chain: &[Step], start: usize, end: usize) -> Option<(usize, usize)> {
    let mut bounds = (start, end);
    for step in chain.iter().rev() {
        bounds = step.to_previous(bounds.0, bounds.1)?;
    }
    (bounds.0 < bounds.1).then_some(bounds)
}

/// The source ranges of `chain` a further decode would still change, each grown
/// to the whole source token around it. What NORM-2 masks at its pass cap.
fn still_encoded(chain: &[Step]) -> Vec<(usize, usize)> {
    let Some(last) = chain.last() else {
        return Vec::new();
    };
    decode::tokens_still_encoded(last.text())
        .into_iter()
        .filter_map(|(start, end)| chain_bounds(chain, start, end))
        .collect()
}

/// A view's map from a span back to the original text's byte bounds.
type SourceBounds<'a> = dyn Fn(usize, usize) -> Option<(usize, usize)> + 'a;

/// Grow every span that overlaps a run of `runs` (sorted, disjoint) over that
/// whole run. A binary search per span finds its first run: linear-log.
fn widen_over_runs(spans: &mut [Span], runs: &[(usize, usize)]) {
    if runs.is_empty() {
        return;
    }
    for span in spans {
        let mut at = runs.partition_point(|run| run.1 <= span.start);
        while at < runs.len() && runs[at].0 < span.end {
            span.start = span.start.min(runs[at].0);
            span.end = span.end.max(runs[at].1);
            at += 1;
        }
    }
}

/// Whether `source` is one token bracket and nothing else: how a view spells a
/// marker the source wrote plainly, since no fold reads as a bracket.
fn is_bracket(source: &str) -> bool {
    let mut chars = source.chars();
    matches!(chars.next(), Some(PLACEHOLDER_OPEN | PLACEHOLDER_CLOSE)) && chars.next().is_none()
}

/// The whitespace-delimited token of `text` that holds the byte range
/// `(start, end)`. The fail-closed unit of the marker rules: a bracket hides
/// inside a token, so the whole token goes rather than the bracket alone.
fn token_around(text: &str, start: usize, end: usize) -> (usize, usize) {
    let from = text[..start]
        .char_indices()
        .rev()
        .find(|(_, ch)| ch.is_whitespace())
        .map_or(0, |(at, ch)| at + ch.len_utf8());
    let to = text[end..]
        .find(char::is_whitespace)
        .map_or(text.len(), |at| end + at);
    (from, to)
}

/// The whitespace-bounded run of `text` around each marker, merged. `markers`
/// is sorted, so one forward pass is linear.
fn marker_runs(text: &str, markers: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for &(start, end) in markers {
        let to = |end: usize| {
            text[end..]
                .find(char::is_whitespace)
                .map_or(text.len(), |at| end + at)
        };
        match runs.last_mut() {
            Some(last) if start < last.1 => {
                if end > last.1 {
                    last.1 = to(end);
                }
            }
            last => {
                let floor = last.map_or(0, |last| last.1);
                let from = text[floor..start]
                    .char_indices()
                    .rev()
                    .find(|(_, c)| c.is_whitespace())
                    .map_or(floor, |(at, c)| floor + at + c.len_utf8());
                runs.push((from, to(end)));
            }
        }
    }
    runs
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Incrementally builds a [`Registry`].
pub struct RegistryBuilder {
    recognizers: Vec<Box<dyn Recognizer>>,
    context: ContextEnhancer,
    thresholds: Thresholds,
    email_layer: Option<EmailLayer>,
}

impl RegistryBuilder {
    /// Mount a recogniser.
    pub fn with_recognizer<R: Recognizer + 'static>(mut self, recognizer: R) -> Self {
        self.recognizers.push(Box::new(recognizer));
        self
    }

    /// Mount an already-boxed recogniser.
    pub fn with_boxed_recognizer(mut self, recognizer: Box<dyn Recognizer>) -> Self {
        self.recognizers.push(recognizer);
        self
    }

    /// Mount every recogniser in the crate, including the unverified ones.
    pub fn with_all(mut self) -> Self {
        self.recognizers.extend(recognizers::all_recognizers());
        self
    }

    /// Override the context enhancer.
    pub fn context(mut self, context: ContextEnhancer) -> Self {
        self.context = context;
        self
    }

    /// Override the thresholds.
    pub fn thresholds(mut self, thresholds: Thresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Mount a custom email-aware layer.
    pub fn email_layer(mut self, email_layer: EmailLayer) -> Self {
        self.email_layer = Some(email_layer);
        self
    }

    /// Turn the email-aware layer off, reproducing the pre-1e pipeline.
    pub fn without_email_layer(mut self) -> Self {
        self.email_layer = None;
        self
    }

    /// Mask bare first names again (default `false`; config key `[privacy]
    /// mask_first_names`).
    ///
    /// The owner decision of 2026-10-09 keeps bare given names in clear; this
    /// switch restores the stricter pre-decision behaviour. A registry built
    /// without the email layer stays without it.
    pub fn mask_first_names(mut self, mask_first_names: bool) -> Self {
        self.email_layer = self
            .email_layer
            .map(|layer| layer.with_first_names(mask_first_names));
        self
    }

    /// Finish the registry.
    pub fn build(self) -> Registry {
        Registry {
            recognizers: self.recognizers,
            context: self.context,
            thresholds: self.thresholds,
            email_layer: self.email_layer,
            keep_names: true,
        }
    }
}

/// The recogniser label of a marker run that splices a word: it fails closed.
pub(crate) const MARKER_RUN: &str = "marker";

/// The label of a prohibited region a name widened, for a registry without names.
pub(crate) const NAME_WIDENED: &str = "name-widened";

/// Whether `region` holds a letter or digit no span of `plain` (sorted,
/// disjoint) covers. One cursor over the plain spans the region overlaps.
fn adds_readable(text: &str, region: &Span, plain: &[Span]) -> bool {
    let mut at = plain.partition_point(|span| span.end <= region.start);
    let mut cursor = region.start;
    while cursor < region.end {
        let next = plain.get(at).filter(|span| span.start < region.end);
        let gap_end = next.map_or(region.end, |span| span.start.max(cursor));
        if text[cursor..gap_end].chars().any(char::is_alphanumeric) {
            return true;
        }
        let Some(span) = next else { break };
        cursor = cursor.max(span.end);
        at += 1;
    }
    false
}

/// Whether a span lies on UTF-8 boundaries and covers non-blank text.
///
/// Presidio's contract: a span whose `text[start..end]` is not the value
/// is dropped. Without a separate value we enforce the observable half: byte
/// ranges inside the text, on character boundaries, holding something other
/// than whitespace.
pub fn span_is_well_formed(text: &str, span: &Span) -> bool {
    if span.start >= span.end || span.end > text.len() {
        return false;
    }
    if !text.is_char_boundary(span.start) || !text.is_char_boundary(span.end) {
        return false;
    }
    let value = &text[span.start..span.end];
    !value.trim().is_empty()
}

/// Resolve overlaps into the union of every overlapping span (P1-1, P2-5).
///
/// Two spans become one region only when they overlap. Adjacent spans of
/// different kinds stay separate, so a display name and the e-mail address
/// beside it keep their own tokens (the hero path fills `attendee_name` and
/// `attendee_email` separately). The region's kind is the highest-priority kind
/// among the members ([`EntityKind::mask_priority`]) and its score is the
/// highest member score.
///
/// A `PERSON` span that overlaps a deterministic span becomes one region with
/// that span's kind, so a name inside an e-mail address is masked as the address
/// and leaves no fragment in clear. A `PERSON` span that does not overlap a
/// deterministic span is its own region, so a name alone in clear text keeps its
/// `PERSON` label. The result is non-overlapping, ordered by start offset, and
/// its byte coverage is exactly [`masked_regions`] on the same input.
pub fn resolve_overlaps(spans: Vec<Span>) -> Vec<Span> {
    merge_regions(spans.into_iter().filter(|span| !span.is_empty()).collect())
}

/// Give each region of `regions` (ordered, disjoint: [`resolve_overlaps`]) the
/// kind of the prohibited span of `spans` overlapping it with the lowest
/// `(mask_priority, kind)`, the first in `spans` order on a tie, and drop its
/// person; returns which regions hold one. A labelled date of birth also lends
/// its origin, the only one that is prohibited. `spans` may be in any order and
/// overlap. One sorted sweep: each span visits only the regions it overlaps,
/// found by binary search, so a text dense with prohibited values stays
/// linear-log instead of regions x spans.
pub(crate) fn label_prohibited(regions: &mut [Span], spans: &[Span]) -> Vec<bool> {
    let key = |span: &Span| (span.kind.mask_priority(), span.kind);
    let mut best: Vec<Option<&Span>> = vec![None; regions.len()];
    for span in spans.iter().filter(|span| span.is_prohibited()) {
        let first = regions.partition_point(|region| region.end <= span.start);
        for (region, slot) in regions[first..].iter().zip(&mut best[first..]) {
            if region.start >= span.end {
                break;
            }
            if slot.is_none_or(|old| key(span) < key(old)) {
                *slot = Some(span);
            }
        }
    }
    for (region, best) in regions.iter_mut().zip(&best) {
        if let Some(best) = best {
            region.kind = best.kind;
            if best.kind == EntityKind::DateOfBirth {
                region.recognizer = best.recognizer;
            }
            region.person_id = None;
        }
    }
    best.iter().map(Option::is_some).collect()
}

/// The non-overlapping regions to mask: union of every overlapping span of
/// every kind.
///
/// [`crate::Anonymizer`] uses this view so each byte is masked exactly once with
/// the highest-priority kind. Since [`resolve_overlaps`] already merges every
/// overlap into the exact union, this is the same region set; it is kept as the
/// explicit masking view the anonymizer reads.
pub(crate) fn masked_regions(spans: Vec<Span>) -> Vec<Span> {
    merge_regions(spans.into_iter().filter(|span| !span.is_empty()).collect())
}

/// Extend every `PERSON` span over the adjacent capitalised name tokens.
///
/// A detector may flag only part of a multi-token name — the given name alone
/// (`Camille` in `Camille Exemple`), or the family name alone. Masking only
/// that part leaves the rest of the name in clear, so the region grows over the
/// neighbouring capitalised tokens. Joiners (`-`, `'`, `’`) and the zero-width
/// and non-breaking separators are crossed; an address boundary (`@`, `.`,
/// `<`, `>`, `(`, `"`) is not.
fn expand_person_spans(text: &str, spans: Vec<Span>) -> Vec<Span> {
    spans
        .into_iter()
        .map(|mut span| {
            if span.kind != EntityKind::Person {
                return span;
            }
            while let Some(end) = next_capitalised_token_end(text, span.end) {
                span.end = end;
            }
            span
        })
        .collect()
}

/// Extend every `PERSON` span over the capitalised words it is joined to by a
/// hyphen, with no space: `Smit` → `Smit-Vosloo` (and chains such as
/// `Halm-Berg-Achterberg`), and `Vosloo` → `Smit-Vosloo` backward.
///
/// A recogniser, the model above all, may flag only one half of a hyphenated
/// surname; the other half would stay in clear. A lower-case word (`Smit-based`),
/// a digit (`COVID-19`) and whitespace stop the growth. Every detector's spans
/// go through this, so each caller gets the same behaviour.
pub(crate) fn extend_hyphenated_persons(text: &str, spans: Vec<Span>) -> Vec<Span> {
    spans
        .into_iter()
        .map(|mut span| {
            if span.kind != EntityKind::Person || !span_is_well_formed(text, &span) {
                return span;
            }
            while let Some(end) = hyphenated_word_after(text, span.end) {
                span.end = end;
            }
            while let Some(start) = hyphenated_word_before(text, span.start) {
                span.start = start;
            }
            span
        })
        .collect()
}

/// The hyphens that join the two parts of a surname: ASCII, U+2010, U+2011.
fn is_hyphen(ch: char) -> bool {
    matches!(ch, '-' | '\u{2010}' | '\u{2011}')
}

/// A letter of a name word, or an apostrophe between two letters (`O'Brien`).
fn is_word_letter(text: &str, at: usize, ch: char) -> bool {
    ch.is_alphabetic()
        || (matches!(ch, '\'' | '\u{2019}')
            && text[..at]
                .chars()
                .next_back()
                .is_some_and(char::is_alphabetic)
            && text[at + ch.len_utf8()..]
                .chars()
                .next()
                .is_some_and(char::is_alphabetic))
}

/// The end of the `-Word` right after `from`, when a hyphen follows directly and
/// the word starts with a capital.
fn hyphenated_word_after(text: &str, from: usize) -> Option<usize> {
    let mut chars = text[from..].chars();
    let hyphen = chars.next().filter(|ch| is_hyphen(*ch))?;
    let start = from + hyphen.len_utf8();
    if !text[start..].chars().next()?.is_uppercase() {
        return None;
    }
    let mut end = start;
    for ch in text[start..].chars() {
        if !is_word_letter(text, end, ch) {
            break;
        }
        end += ch.len_utf8();
    }
    // An address, not a name part: `Smit-Vosloo@x.test`.
    if text[end..].starts_with('@') {
        return None;
    }
    Some(end)
}

/// The start of the `Word-` right before `from`, when a hyphen precedes directly
/// and the word starts with a capital.
fn hyphenated_word_before(text: &str, from: usize) -> Option<usize> {
    let hyphen = text[..from]
        .chars()
        .next_back()
        .filter(|ch| is_hyphen(*ch))?;
    let word_end = from - hyphen.len_utf8();
    let mut start = word_end;
    for (at, ch) in text[..word_end].char_indices().rev() {
        if !is_word_letter(text, at, ch) {
            break;
        }
        start = at;
    }
    if start == word_end || !text[start..].chars().next()?.is_uppercase() {
        return None;
    }
    Some(start)
}

/// The end of the capitalised name token that follows `from` across one
/// separator run, or `None` when the next thing is not one.
fn next_capitalised_token_end(text: &str, from: usize) -> Option<usize> {
    let mut cursor = from;
    let mut crossed = false;
    for ch in text[from..].chars() {
        if is_name_separator(ch) {
            cursor += ch.len_utf8();
            crossed = true;
        } else {
            break;
        }
    }
    if !crossed {
        return None;
    }
    // Never cross into a word that carries an address or a list separator:
    // `Camille@x` and `Exemple,` are boundaries, not name parts.
    let word_end = text[cursor..]
        .find(char::is_whitespace)
        .map(|offset| cursor + offset)
        .unwrap_or(text.len());
    let word = &text[cursor..word_end];
    if word.contains('@') || word.contains(',') {
        return None;
    }
    let mut end = cursor;
    let mut first = true;
    for ch in text[cursor..].chars() {
        if first {
            if !ch.is_uppercase() {
                return None;
            }
            first = false;
            end += ch.len_utf8();
        } else if ch.is_alphabetic() || is_name_joiner(ch) {
            end += ch.len_utf8();
        } else {
            break;
        }
    }
    if end == cursor {
        None
    } else {
        Some(end)
    }
}

/// The horizontal separators a name region may cross: a space, a non-breaking
/// space and the zero-width characters. A line break is not crossed.
fn is_name_separator(ch: char) -> bool {
    matches!(ch, ' ' | '\u{00A0}' | '\u{2007}' | '\u{202F}')
        || is_name_joiner(ch)
        || is_default_ignorable(ch)
}

/// The characters that join the parts of one name.
fn is_name_joiner(ch: char) -> bool {
    matches!(ch, '-' | '\'' | '\u{2019}' | '\u{02BC}' | '`')
}

/// Merge spans: overlapping members become one region. Touching spans of
/// different kinds stay separate.
fn merge_regions(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by_key(|span| (span.start, span.end));
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(last) = merged.last_mut() {
            if span.start < last.end {
                last.end = last.end.max(span.end);
                if wins_over(&span, last) {
                    last.kind = span.kind;
                    last.recognizer = span.recognizer;
                }
                last.score = last.score.max(span.score);
                // A region keeps a person only when every member names that person.
                if last.person_id != span.person_id {
                    last.person_id = None;
                }
                continue;
            }
        }
        merged.push(span);
    }
    merged
}

/// Whether `candidate` should take the label of a span it overlaps.
///
/// A passport-origin span outranks an IBAN candidate (P3, kind labels), even
/// though the registry relabels it `NATIONAL_ID`. It does *not* steal the label
/// from a more specific national-id rule (a cued TAJ or NIR), and the kind
/// priority decides every other pair; on an equal priority the specific label
/// beats the generic passport fallback, otherwise the span that already won
/// keeps the label.
///
/// A prohibited span ([`Span::is_prohibited`]) outranks every kind Open
/// mode leaves in clear before any of this, so a region that holds a health
/// term, an IBAN, an ID or a secret is removed in every mode, whatever e-mail,
/// phone, URL or address it overlaps (K-SPAN-PRIORITY).
fn wins_over(candidate: &Span, current: &Span) -> bool {
    if candidate.is_prohibited() != current.is_prohibited() {
        return candidate.is_prohibited();
    }
    let candidate_passport = candidate.recognizer == "passport_mrz";
    let current_passport = current.recognizer == "passport_mrz";
    if candidate_passport && current.kind == EntityKind::Iban {
        return true;
    }
    if current_passport && candidate.kind == EntityKind::Iban {
        return false;
    }
    let candidate_priority = candidate.kind.mask_priority();
    let current_priority = current.kind.mask_priority();
    if candidate_priority != current_priority {
        return candidate_priority < current_priority;
    }
    current_passport && !candidate_passport
}

/// Split every span longer than [`MAX_SPAN_BYTES`] (a secret: longer than
/// [`MAX_KEY_SPAN_BYTES`]) into consecutive pieces of at most [`MAX_SPAN_BYTES`]
/// bytes, each ending on a character boundary of `text`.
///
/// The pieces keep the parent span's kind, score and recogniser, so a merged
/// union cannot be used to mask an arbitrarily large region in one token while
/// still masking all of it. `text` must contain the span bounds on char
/// boundaries (spans are validated upstream).
pub fn split_long_spans(text: &str, spans: Vec<Span>) -> Vec<Span> {
    let mut out = Vec::with_capacity(spans.len());
    for span in spans {
        let whole = if span.kind == EntityKind::Secret {
            MAX_KEY_SPAN_BYTES
        } else {
            MAX_SPAN_BYTES
        };
        if span.len() <= whole {
            out.push(span);
            continue;
        }
        let mut start = span.start;
        while start < span.end {
            let mut end = (start + MAX_SPAN_BYTES).min(span.end);
            while end > start && !text.is_char_boundary(end) {
                end -= 1;
            }
            if end <= start {
                // A single code point longer than the cap: keep it whole.
                end = text[start..]
                    .char_indices()
                    .nth(1)
                    .map(|(offset, _)| start + offset)
                    .unwrap_or(span.end);
            }
            let mut piece = Span::new(span.kind, start, end, span.score, span.recognizer);
            piece.person_id = span.person_id;
            out.push(piece);
            start = end;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(kind: EntityKind, start: usize, end: usize, score: f32) -> Span {
        Span::new(kind, start, end, score, "test")
    }

    #[test]
    fn overlapping_spans_merge_and_priority_picks_the_kind() {
        let spans = vec![
            span(EntityKind::Email, 0, 5, 0.9),
            span(EntityKind::Url, 0, 9, 0.4),
            span(EntityKind::Phone, 20, 25, 0.3),
            span(EntityKind::Iban, 20, 25, 0.8),
        ];
        let kept = resolve_overlaps(spans);
        assert_eq!(kept.len(), 2);
        // Email outranks Url, Iban outranks Phone.
        assert_eq!(kept[0].kind, EntityKind::Email);
        assert_eq!((kept[0].start, kept[0].end), (0, 9));
        assert_eq!(kept[1].kind, EntityKind::Iban);
    }

    #[test]
    fn touching_spans_of_different_kinds_stay_separate() {
        let spans = vec![
            span(EntityKind::Email, 10, 20, 1.0),
            span(EntityKind::Phone, 0, 10, 1.0),
        ];
        let kept = resolve_overlaps(spans);
        assert_eq!(kept.len(), 2);
        assert_eq!(
            (kept[0].kind, kept[0].start, kept[0].end),
            (EntityKind::Phone, 0, 10)
        );
        assert_eq!(
            (kept[1].kind, kept[1].start, kept[1].end),
            (EntityKind::Email, 10, 20)
        );
    }

    #[test]
    fn a_person_inside_a_deterministic_span_takes_its_kind_without_a_gap() {
        let spans = vec![
            span(EntityKind::Email, 0, 12, 1.0),
            span(EntityKind::Person, 3, 8, 0.7),
        ];
        let kept = resolve_overlaps(spans);
        // One exact union region: no separate PERSON edge to fall short of a
        // gold span that straddles the boundary.
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].start, kept[0].end), (0, 12));
        assert_eq!(kept[0].kind, EntityKind::Email);
    }

    #[test]
    fn a_name_right_after_a_phone_stays_its_own_region() {
        let spans = vec![
            span(EntityKind::Phone, 0, 10, 1.0),
            span(EntityKind::Person, 10, 15, 0.7),
        ];
        let kept = resolve_overlaps(spans);
        assert_eq!(kept.len(), 2);
        assert_eq!(
            (kept[0].kind, kept[0].start, kept[0].end),
            (EntityKind::Phone, 0, 10)
        );
        assert_eq!(
            (kept[1].kind, kept[1].start, kept[1].end),
            (EntityKind::Person, 10, 15)
        );
    }

    #[test]
    fn a_person_on_its_own_keeps_its_kind() {
        let spans = vec![
            span(EntityKind::Phone, 0, 10, 1.0),
            span(EntityKind::Person, 12, 17, 0.7),
        ];
        let kept = resolve_overlaps(spans);
        assert_eq!(kept.len(), 2);
        assert_eq!(
            (kept[1].kind, kept[1].start, kept[1].end),
            (EntityKind::Person, 12, 17)
        );
    }

    #[test]
    fn contained_span_widens_the_union_instead_of_being_dropped() {
        let spans = vec![
            span(EntityKind::Url, 0, 30, 0.9),
            span(EntityKind::Email, 5, 35, 1.0),
        ];
        let kept = resolve_overlaps(spans);
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].start, kept[0].end), (0, 35));
        assert_eq!(kept[0].kind, EntityKind::Email);
    }

    #[test]
    fn partial_overlap_masks_the_whole_union() {
        let spans = vec![
            span(EntityKind::Phone, 0, 10, 1.0),
            span(EntityKind::Email, 8, 20, 1.0),
        ];
        let kept = resolve_overlaps(spans);
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].start, kept[0].end), (0, 20));
    }

    #[test]
    fn passport_origin_outranks_iban_and_keeps_its_end() {
        // The registry relabels the passport hit `NATIONAL_ID`, so only the
        // originating recogniser can carry `passport > iban` (P3).
        let spans = vec![
            span(EntityKind::Iban, 10, 21, 0.55),
            span(EntityKind::NationalId, 10, 21, 0.6),
        ]
        .into_iter()
        .map(|mut span| {
            if span.kind == EntityKind::NationalId {
                span.recognizer = "passport_mrz";
            } else {
                span.recognizer = "iban";
            }
            span
        })
        .collect();
        let kept = resolve_overlaps(spans);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kind, EntityKind::NationalId);
        assert_eq!(kept[0].recognizer, "passport_mrz");
        // The end is the passport end.
        assert_eq!((kept[0].start, kept[0].end), (10, 21));
    }

    #[test]
    fn specific_national_id_keeps_its_label_over_the_passport_fallback() {
        let mut passport = span(EntityKind::NationalId, 0, 13, 0.6);
        passport.recognizer = "passport_mrz";
        let taj = span(EntityKind::HuTaj, 4, 13, 1.0);
        let kept = resolve_overlaps(vec![passport, taj]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kind, EntityKind::HuTaj);
        assert_eq!(kept[0].recognizer, "test");
        assert_eq!((kept[0].start, kept[0].end), (0, 13));
    }

    #[test]
    fn generic_national_id_outranks_company_ids_and_phones() {
        let spans = vec![
            span(EntityKind::FrVat, 0, 13, 1.0),
            span(EntityKind::Phone, 2, 11, 0.5),
            span(EntityKind::NationalId, 0, 11, 0.6),
        ];
        let kept = resolve_overlaps(spans);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kind, EntityKind::NationalId);
        assert_eq!((kept[0].start, kept[0].end), (0, 13));
    }

    #[test]
    fn well_formed_checks_boundaries() {
        let text = "héllo";
        assert!(span_is_well_formed(
            text,
            &span(EntityKind::Email, 0, 6, 1.0)
        ));
        assert!(!span_is_well_formed(
            text,
            &span(EntityKind::Email, 2, 3, 1.0)
        ));
        assert!(!span_is_well_formed(
            text,
            &span(EntityKind::Email, 0, 0, 1.0)
        ));
        assert!(!span_is_well_formed(
            text,
            &span(EntityKind::Email, 0, 99, 1.0)
        ));
    }

    #[test]
    fn default_registry_runs_every_recognizer() {
        let registry = Registry::new();
        assert!(!registry.recognizers().is_empty());
        assert!(registry
            .recognizers()
            .iter()
            .all(|recognizer| recognizer.enabled_by_default()));
    }

    #[test]
    fn builder_mounts_all_recognizers() {
        let registry = Registry::builder().with_all().build();
        assert_eq!(
            registry.recognizers().len(),
            Registry::new().recognizers().len()
        );
        assert!(registry
            .recognizers()
            .iter()
            .any(|recognizer| !recognizer.verified()));
    }

    #[test]
    fn long_spans_split_on_char_boundaries() {
        let text = "x".repeat(300);
        let span = Span::new(EntityKind::NationalId, 0, 300, 1.0, "test");
        let split = split_long_spans(&text, vec![span]);
        assert!(split.iter().all(|span| span.len() <= MAX_SPAN_BYTES));
        assert_eq!(split.first().map(|span| span.start), Some(0));
        assert_eq!(split.last().map(|span| span.end), Some(300));
        assert!(split
            .iter()
            .all(|span| text.is_char_boundary(span.start) && text.is_char_boundary(span.end)));
    }

    #[test]
    fn email_layer_is_mounted_by_default_and_masks_a_header_name() {
        assert!(Registry::new().email_layer().is_some());
        assert!(!Registry::new()
            .email_layer()
            .expect("email layer")
            .masks_first_names());
        // Wiring check: the default path runs the email layer, so a sender
        // display name with no deterministic recogniser is still masked.
        let text = "De : Océane Mabille <oceane.mabille@example.invalid>";
        let spans = Registry::new().analyze(text);
        assert!(
            spans.iter().any(|span| {
                span.kind == EntityKind::Person && &text[span.start..span.end] == "Océane Mabille"
            }),
            "{spans:?}"
        );
        let without = Registry::builder().with_all().without_email_layer().build();
        assert!(without.email_layer().is_none());
        assert!(without
            .analyze(text)
            .iter()
            .all(|span| span.kind != EntityKind::Person));
    }

    #[test]
    fn bare_first_names_are_off_by_default_and_the_switch_restores_them() {
        // A lone given name in a greeting is not a person by default. A
        // signature singleton is a different case: that context always keeps
        // the span (see `signature_and_header_singletons_always_stay`).
        let text = "Bonjour Théo,\n\nThéo";
        assert!(Registry::new()
            .analyze(text)
            .iter()
            .all(|span| span.kind != EntityKind::Person));
        let strict = Registry::builder()
            .with_all()
            .mask_first_names(true)
            .build();
        assert!(strict
            .analyze(text)
            .iter()
            .any(|span| span.kind == EntityKind::Person));
        // A full name is always masked, whatever the switch.
        let full = "Cordialement,\nThéo Lambrecht";
        assert!(Registry::new()
            .analyze(full)
            .iter()
            .any(|span| span.kind == EntityKind::Person));
    }

    /// Random overlapping spans over multi-byte text: the masked bytes are
    /// exactly the union of the spans, with no off-by-one at a char boundary.
    #[test]
    fn random_overlapping_spans_mask_the_exact_union() {
        let text = "aé—•Ωz bonjour Élise Ünïcode 漢字 end";
        let boundaries: Vec<usize> = text
            .char_indices()
            .map(|(index, _)| index)
            .chain(std::iter::once(text.len()))
            .collect();
        // A small deterministic LCG: no dependency, reproducible.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = |bound: usize| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((state >> 33) as usize) % bound
        };
        for _ in 0..500 {
            let count = 1 + next(6);
            let mut spans = Vec::new();
            for _ in 0..count {
                let a = boundaries[next(boundaries.len())];
                let b = boundaries[next(boundaries.len())];
                let (start, end) = if a <= b { (a, b) } else { (b, a) };
                if start == end {
                    continue;
                }
                let kind = [
                    EntityKind::Person,
                    EntityKind::Email,
                    EntityKind::Address,
                    EntityKind::Phone,
                ][next(4)];
                spans.push(Span::new(kind, start, end, 0.9, "test"));
            }
            let regions = resolve_overlaps(spans.clone());
            // Build the expected union byte set from the raw spans.
            let mut expected = vec![false; text.len()];
            for span in &spans {
                for slot in expected.iter_mut().take(span.end).skip(span.start) {
                    *slot = true;
                }
            }
            let mut covered = vec![false; text.len()];
            for region in &regions {
                assert!(
                    text.is_char_boundary(region.start) && text.is_char_boundary(region.end),
                    "a region must stay on char boundaries: {region:?}"
                );
                for slot in covered.iter_mut().take(region.end).skip(region.start) {
                    *slot = true;
                }
            }
            assert_eq!(covered, expected, "union mismatch for {spans:?}");
            // The regions never overlap each other.
            for pair in regions.windows(2) {
                assert!(pair[0].end <= pair[1].start, "regions overlap: {pair:?}");
            }
            // The masking view is byte-for-byte the same union.
            assert_eq!(
                masked_regions(spans.clone()),
                regions,
                "resolve_overlaps and the masker must agree"
            );
        }
    }

    fn person(text: &str, name: &str) -> Span {
        let start = text.find(name).expect("name in text");
        span(EntityKind::Person, start, start + name.len(), 0.9)
    }

    fn extended<'a>(text: &'a str, name: &str) -> &'a str {
        let spans = extend_hyphenated_persons(text, vec![person(text, name)]);
        &text[spans[0].start..spans[0].end]
    }

    #[test]
    fn a_hyphenated_surname_is_covered_whole_from_either_half() {
        let text = "Anna Smit-Vosloo called";
        assert_eq!(extended(text, "Anna Smit"), "Anna Smit-Vosloo");
        assert_eq!(extended(text, "Vosloo"), "Smit-Vosloo");
        assert_eq!(
            extended("Hi Jean-Pierre Martin,", "Pierre Martin"),
            "Jean-Pierre Martin"
        );
        assert_eq!(extended("Dear Anna-Halm, the", "Anna"), "Anna-Halm");
    }

    #[test]
    fn hyphen_chains_and_unicode_hyphens_are_followed() {
        let text = "Halm-Berg-Achterberg wrote";
        assert_eq!(extended(text, "Halm"), "Halm-Berg-Achterberg");
        assert_eq!(extended(text, "Achterberg"), "Halm-Berg-Achterberg");
        assert_eq!(
            extended("Smit\u{2010}Vosloo\u{2011}Mor", "Smit"),
            "Smit\u{2010}Vosloo\u{2011}Mor"
        );
        assert_eq!(
            extended("Smit-O\u{2019}Brien x", "Smit"),
            "Smit-O\u{2019}Brien"
        );
    }

    #[test]
    fn hyphen_growth_stops_at_lower_case_digits_spaces_and_addresses() {
        assert_eq!(extended("the Smit-based plan", "Smit"), "Smit");
        assert_eq!(extended("the based-Smit plan", "Smit"), "Smit");
        assert_eq!(extended("Smit-19 and COVID-19", "Smit"), "Smit");
        assert_eq!(extended("2024-Smit", "Smit"), "Smit");
        assert_eq!(extended("Smit - Vosloo", "Smit"), "Smit");
        assert_eq!(extended("Smit-\nVosloo", "Smit"), "Smit");
        assert_eq!(extended("Smit-Vosloo@x.test", "Smit"), "Smit");
    }

    #[test]
    fn only_person_spans_grow_over_a_hyphen() {
        let text = "ACME-Corp pays";
        let org = span(EntityKind::Organization, 0, 4, 0.9);
        let out = extend_hyphenated_persons(text, vec![org]);
        assert_eq!((out[0].start, out[0].end), (0, 4));
    }

    #[test]
    fn the_registry_with_a_dictionary_masks_both_halves() {
        let registry = Registry::builder()
            .with_recognizer(std::sync::Arc::new(
                crate::known_names::NameDictionary::new(["Vosloo", "Anna Smit"]).unwrap(),
            ))
            .build();
        let text = "Hi Smit-Vosloo and Anna Smit-Halm, bye";
        let found = registry.analyze(text);
        let covered: Vec<&str> = found.iter().map(|s| &text[s.start..s.end]).collect();
        assert_eq!(covered, ["Smit-Vosloo", "Anna Smit-Halm"]);
    }

    /// The sorted sweep labels every region exactly as main's full scan did
    /// (same kind, same tie, same person drop) on unsorted, overlapping,
    /// empty and reversed spans, and every byte of a prohibited span lies in a
    /// region that holds a prohibited kind (OCR-KERNEL-3a).
    #[test]
    fn label_prohibited_matches_a_full_scan() {
        let kinds = [
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Iban,
            EntityKind::CreditCard,
            EntityKind::Health,
            EntityKind::Secret,
            EntityKind::NationalId,
            EntityKind::Address,
        ];
        let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % bound as u64) as usize
        };
        for round in 0..2_000 {
            let spans: Vec<Span> = (0..1 + round % 24)
                .map(|_| {
                    let start = next(80);
                    let end = if next(10) == 0 {
                        start.saturating_sub(next(3))
                    } else {
                        start + next(12)
                    };
                    let mut span = Span::new(kinds[next(kinds.len())], start, end, 0.9, "t");
                    span.person_id = Some(next(4) as u32);
                    span
                })
                .collect();
            let mut swept = resolve_overlaps(spans.clone());
            let mut scanned = swept.clone();
            let held = label_prohibited(&mut swept, &spans);
            for region in &mut scanned {
                if let Some(best) = spans
                    .iter()
                    .filter(|s| {
                        s.kind.is_prohibited() && s.start < region.end && region.start < s.end
                    })
                    .min_by_key(|s| (s.kind.mask_priority(), s.kind))
                {
                    region.kind = best.kind;
                    region.person_id = None;
                }
            }
            assert_eq!(swept, scanned, "round {round}: {spans:?}");
            for span in spans
                .iter()
                .filter(|s| s.kind.is_prohibited() && !s.is_empty())
            {
                for byte in span.start..span.end {
                    let at = swept.iter().position(|r| r.start <= byte && byte < r.end);
                    assert!(
                        at.is_some_and(|at| held[at] && swept[at].kind.is_prohibited()),
                        "round {round}: byte {byte} of {span:?} in clear"
                    );
                }
            }
        }
    }
}
