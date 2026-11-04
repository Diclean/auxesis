//! Minimal readability: html5ever parses the document, a small scorer picks
//! the main-content container, and a block-aware walker renders plain text.
//!
//! This deliberately models *structure*, not paint: it drops chrome elements
//! (`script`, `style`, `noscript`, `template`, `nav`, `aside`, …), treats a
//! top-level `<header>`/`<footer>` as site chrome rather than an article
//! candidate, prefers `main`/`article`/`[role=main]`, and otherwise scores
//! containers by text volume, paragraph count and link density. The page
//! path does **not** model CSS visibility; see the crate docs. The mail path
//! ([`extract_body_text`]) also drops what an element hides through its own
//! attributes, its inline style or a simple `<style>` rule ([`Sheet`]).

use html5ever::parse_document;
use html5ever::tendril::{StrTendril, Tendril, TendrilSink};
use html5ever::tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::{Attribute, ExpandedName, QualName};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Text pulled out of one HTML document.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Readable {
    /// Document title (`<title>`, falling back to the first `<h1>`).
    pub title: String,
    /// Whitespace-collapsed readable text.
    pub text: String,
    /// True when the extractor stopped early: either the parse was aborted by
    /// the in-parse work budget or wall-clock deadline (the tail was not
    /// parsed), or the walkers dropped content past [`MAX_DOM_DEPTH`] or were
    /// stopped by the deadline.
    pub truncated: bool,
}

/// Parse `html` and extract the readable title and text.
///
/// The whole extraction stops at a wall-clock deadline
/// ([`EXTRACT_WALL_BUDGET`]); see [`extract_readable_before`].
pub fn extract_readable(html: &[u8]) -> Readable {
    extract_readable_before(html, Instant::now() + EXTRACT_WALL_BUDGET)
}

/// [`extract_readable`] with an absolute wall-clock deadline.
///
/// The fetch path passes `min(now + EXTRACT_WALL_BUDGET, fetch deadline)` so
/// that extraction stops when the fetch budget elapses: the blocking task is
/// not cancellable, so without this it would keep burning CPU after the
/// caller has already received [`kernel_net::FetchError::Timeout`].
pub(crate) fn extract_readable_before(html: &[u8], deadline: Instant) -> Readable {
    extract_with_deadline(html, Deadline { limit: deadline }, false)
}

/// [`extract_readable`] for a mail body: no scorer, the same dropped elements
/// and budget, and none of the text a mail client hides through an element's
/// own attributes or inline style ([`hides_subtree`], [`Paint`]). A mail body
/// is all content, so a greeting or a deadline next to a longer paragraph is
/// never dropped like page chrome.
///
/// Only simple `<style>` rules are evaluated ([`Sheet`]), so another rule can
/// still hide text from the reader: mail stays untrusted. `title` ignores
/// visibility; mail callers use `text`.
pub fn extract_body_text(html: &[u8]) -> Readable {
    let limit = Instant::now() + EXTRACT_WALL_BUDGET;
    extract_with_deadline(html, Deadline { limit }, true)
}

/// Which view of the document the walkers render.
#[derive(Clone, Copy)]
enum Mode<'a> {
    /// A web page: the scorer's container, structure only.
    Page,
    /// A mail body: the whole document, minus what its elements hide.
    Mail(&'a Sheet),
}

fn extract_with_deadline(html: &[u8], deadline: Deadline, mail: bool) -> Readable {
    let (dom, parse_aborted) = parse(html, &deadline);
    let sheet = mail.then(|| Sheet::of(&dom.document, &deadline));
    let (root, mode) = match &sheet {
        None => (choose_root(&dom.document, &deadline), Mode::Page),
        // `<html>`, not `<body>`: a hidden `<html>` hides the whole mail.
        Some(sheet) => (
            find_first(&dom.document, "html", 0, &deadline).unwrap_or_else(|| dom.document.clone()),
            Mode::Mail(sheet),
        ),
    };
    let readable = Readable {
        title: title_of(&dom.document, &root, &deadline),
        text: normalize(&render(&root, &deadline, mode)),
        // The walkers below stop at `MAX_DOM_DEPTH`; html5ever can build a
        // deeper tree than the walkers descend (implied `html`/`body`/`tbody`
        // nodes), so flag any content the walkers dropped instead of silently
        // reporting a complete fetch. An expired deadline also means some
        // stage stopped early, so it flags truncation even if nothing was
        // visibly dropped (fail closed).
        truncated: parse_aborted
            || deadline.expired()
            || depth_exceeds(&dom.document, &deadline, mode)
            || sheet.as_ref().is_some_and(|sheet| sheet.overflow),
    };
    // Hostile pages can nest tens of thousands of elements; tear the DOM
    // down with an explicit stack so recursive `Drop` cannot overflow ours.
    // This is linear in the node count and intentionally not deadline-checked.
    dismantle(&dom.document);
    readable
}

/// True when any node in `root` sits deeper than [`MAX_DOM_DEPTH`], i.e. the
/// walkers' own bound would drop content.
///
/// Subtrees the walkers skip (dropped elements such as `<template>`, and
/// top-level site chrome such as `<header>`/`<footer>` directly under
/// `<body>`) are skipped here too, so a deep tree hidden inside skipped
/// chrome does not report truncation when nothing was lost from the output.
fn depth_exceeds(root: &Handle, deadline: &Deadline, mode: Mode) -> bool {
    let mut stack = vec![(root.clone(), 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_DOM_DEPTH {
            return true;
        }
        if deadline.expired() {
            // The walkers were cut short; `extract_with_deadline` flags
            // `truncated` for an expired deadline unconditionally.
            return false;
        }
        if let Some(tag) = tag_name(&node) {
            if walker_skips(&node, tag, mode) {
                continue;
            }
        }
        for child in node.children.borrow().iter() {
            stack.push((child.clone(), depth + 1));
        }
    }
    false
}

/// Deepest DOM level the walkers descend to. Browsers cap the open-element
/// stack around this size; below it nothing realistic lives.
const MAX_DOM_DEPTH: usize = 512;

/// Iteratively detach every node from the tree before `RcDom` drops. Without
/// this, a 50k-deep document would recurse through `Rc<Node>::drop` and
/// abort the process.
fn dismantle(root: &Handle) {
    let mut stack = vec![root.clone()];
    while let Some(node) = stack.pop() {
        let children = std::mem::take(&mut *node.children.borrow_mut());
        for child in children {
            child.parent.set(None);
            stack.push(child);
        }
    }
}

/// Elements that never contribute readable content.
///
/// `header` and `footer` are deliberately absent: on the dominant blog/CMS
/// shape the article's own `<header>` holds the `<h1>` and byline and its
/// `<footer>` holds the tags/dateline, so dropping them discarded the
/// headline the model is asked for. A top-level `<header>`/`<footer>` (site
/// chrome) is instead excluded from the container candidates by the scorer.
const DROPPED: &[&str] = &[
    "script", "style", "noscript", "template", "head", "title", "meta", "link", "base", "nav",
    "aside", "iframe", "frame", "frameset", "svg", "math", "canvas", "object", "embed", "form",
    "button", "select", "option", "optgroup", "textarea", "input", "label", "audio", "video",
    "source", "track", "map", "area", "dialog", "menu", "noembed", "noframes", "datalist",
];

/// Block-level elements: each starts and ends its own paragraph.
const BLOCK: &[&str] = &[
    "address",
    "article",
    "blockquote",
    "dd",
    "details",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "li",
    "main",
    "ol",
    "p",
    "pre",
    "section",
    "summary",
    "table",
    "tbody",
    "tfoot",
    "thead",
    "tr",
    "ul",
];

fn is_dropped(tag: &str) -> bool {
    DROPPED.contains(&tag)
}

fn is_block(tag: &str) -> bool {
    BLOCK.contains(&tag)
}

fn is_paragraph(tag: &str) -> bool {
    matches!(
        tag,
        "p" | "pre" | "blockquote" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "figcaption"
    )
}

/// A `<header>`/`<footer>` that is a direct child of `<body>` is site chrome
/// (logo, tagline, nav, colophon), not an article candidate, so it must not
/// win the scorer and displace the real content, and the walkers must not
/// render it. The article's *own* header and footer sit inside the chosen
/// container (a parent other than `body`), so they are kept.
fn is_site_chrome(node: &Handle) -> bool {
    if !matches!(tag_name(node), Some("header" | "footer")) {
        return false;
    }
    // `parent` is a `Cell<Option<Weak<_>>>`: borrow it out and put it back
    // (single-threaded walker; no concurrent mutation).
    let parent = node.parent.take();
    let site = parent
        .as_ref()
        .and_then(|weak| weak.upgrade())
        .is_some_and(|parent| tag_name(&parent) == Some("body"));
    node.parent.set(parent);
    site
}

/// True when a walker must not descend into `node`: an element that never
/// contributes readable content ([`is_dropped`]), top-level site chrome, or
/// in a mail body an element hidden with its subtree ([`hides_subtree`]).
/// All three walkers (`scan`, `render_into`, `depth_exceeds`) share this
/// predicate so a skip rule cannot be taught to only one of them.
fn walker_skips(node: &Handle, tag: &str, mode: Mode) -> bool {
    is_dropped(tag)
        || is_site_chrome(node)
        || matches!(mode, Mode::Mail(sheet) if hides_subtree(node, sheet))
}

/// True when a mail client shows nothing of `node` or its subtree, whatever
/// the children say: the `hidden` attribute, `aria-hidden="true"`, or a
/// `display:none`, `opacity:0`, or a zero `height`/`width` (or their `max-`
/// forms) with an `overflow` that clips, inline or from a [`Sheet`] rule.
fn hides_subtree(node: &Handle, sheet: &Sheet) -> bool {
    sheet.overflow
        || attr(node, "hidden").is_some()
        || attr(node, "aria-hidden").is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
        || style(node, sheet, BASE_FONT_PX).gone
}

/// Font sizes in CSS px: the root size, and the smallest size whose text a
/// reader is taken to see.
const BASE_FONT_PX: f64 = 16.0;
const MIN_FONT_PX: f64 = 6.0;

/// Inherited text visibility in a mail body. Unlike [`hides_subtree`], CSS
/// lets a descendant undo these with its own declaration: responsive mail
/// layouts wrap whole columns in `font-size:0` and set the size again
/// inside, so they hide text, not elements.
#[derive(Clone, Copy)]
struct Paint {
    font_px: f64,
    invisible: bool,
}

impl Paint {
    /// The paint inside `node`, an element.
    fn under(self, node: &Handle, sheet: &Sheet) -> Paint {
        let style = style(node, sheet, self.font_px);
        Paint {
            font_px: style.font_px.unwrap_or(self.font_px),
            invisible: style.invisible.unwrap_or(self.invisible),
        }
    }
}

/// What one element's inline `style` and the [`Sheet`] rules it matches say
/// about visibility. Declarations are read literally: comments and strings
/// are skipped, but CSS escapes, `calc()` and `var()` are not evaluated. A
/// hiding declaration beats a later one that shows (drop more, never less).
#[derive(Default)]
struct Style {
    /// See [`hides_subtree`].
    gone: bool,
    /// `font-size` in px, the smallest one declared.
    font_px: Option<f64>,
    /// `visibility`: `Some(true)` for `hidden` or `collapse`.
    invisible: Option<bool>,
}

/// The [`Style`] of `node` inside a parent whose font size is `parent_px`.
fn style(node: &Handle, sheet: &Sheet, parent_px: f64) -> Style {
    let mut style = declarations(&clean(&attr(node, "style").unwrap_or_default()), parent_px);
    if sheet.rules.is_empty() {
        return style;
    }
    let tag = tag_name(node).unwrap_or_default();
    let id = attr(node, "id").unwrap_or_default().to_ascii_lowercase();
    let class = attr(node, "class").unwrap_or_default().to_ascii_lowercase();
    let classes: HashSet<&str> = class.split_ascii_whitespace().collect();
    for (selectors, rule) in &sheet.rules {
        if selectors
            .iter()
            .any(|selector| selects(selector, tag, &id, &classes))
        {
            style.gone |= rule.gone;
            style.font_px = smaller(style.font_px, rule.font_px);
            style.invisible = style.invisible.max(rule.invisible);
        }
    }
    style
}

/// The [`Style`] of one block of [`clean`]ed declarations. An escape or an
/// entity in a property name or in a value read here, or a function in a
/// `display`, `visibility` or `opacity` value, makes the element gone: a
/// mail client may resolve it to a hiding value (fail closed).
fn declarations(css: &str, parent_px: f64) -> Style {
    let mut style = Style::default();
    let (mut zero_box, mut clipped) = (false, false);
    for declaration in css.split(';') {
        let (name, value) = declaration.split_once(':').unwrap_or((declaration, ""));
        let value = value.split('!').next().unwrap_or_default().trim();
        let escaped = value.contains(['\\', '&']);
        let opaque = escaped || value.contains('(');
        match name.trim() {
            name if name.contains(['\\', '&']) => style.gone = true,
            "display" => style.gone |= opaque || value == "none",
            "opacity" => style.gone |= opaque || number(value).is_some_and(|(n, _)| n <= 0.0),
            "height" | "max-height" | "width" | "max-width" => {
                zero_box |= escaped || number(value).is_some_and(|(n, _)| n == 0.0);
            }
            "overflow" | "overflow-x" | "overflow-y" => {
                clipped |= escaped
                    || value
                        .split_whitespace()
                        .any(|word| matches!(word, "hidden" | "clip" | "auto" | "scroll"));
            }
            "visibility" => match value {
                _ if opaque => style.gone = true,
                "hidden" | "collapse" => style.invisible = Some(true),
                "visible" | "initial" => style.invisible = style.invisible.or(Some(false)),
                _ => {}
            },
            "font-size" if escaped => style.gone = true,
            "font-size" => style.font_px = smaller(style.font_px, font_px(value, parent_px)),
            "font" => {
                // The shorthand's size is its first number with a unit, or a zero.
                let mut words = value.split(|c: char| c.is_whitespace() || c == '/');
                let size =
                    words.find(|w| number(w).is_some_and(|(n, u)| n == 0.0 || !u.is_empty()));
                style.font_px = smaller(style.font_px, size.and_then(|w| font_px(w, parent_px)));
            }
            _ => {}
        }
    }
    style.gone |= zero_box && clipped;
    style
}

fn smaller(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    a.into_iter().chain(b).reduce(f64::min)
}

/// `css` lowercased, with each comment replaced by a space and the inside of
/// each string and unquoted `url(…)` by spaces, so that no `;`, brace, quote
/// or `/*` in them ends a declaration or a rule. An escape keeps its `\`.
fn clean(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css.chars();
    // The quote or `)` that ends the string or `url(` being read.
    let mut close = None;
    while let Some(c) = rest.next() {
        let url = c == '(' && out.ends_with("url");
        match close {
            _ if c == '\\' => {
                out.push_str(if close.is_some() { "  " } else { "\\_" });
                rest.next();
            }
            Some(end) if c == end || (end != ')' && matches!(c, '\n' | '\r' | '\x0c')) => {
                close = None;
                out.push(c);
            }
            Some(_) => out.push(' '),
            None if c == '"'
                || c == '\''
                || (url && !rest.as_str().trim_start().starts_with(['"', '\''])) =>
            {
                close = Some(if url { ')' } else { c });
                out.push(c);
            }
            None if c == '/' && rest.as_str().starts_with('*') => {
                out.push(' ');
                let comment = &rest.as_str()[1..];
                rest = comment
                    .find("*/")
                    .map_or("", |end| &comment[end + 2..])
                    .chars();
            }
            None => out.push(c.to_ascii_lowercase()),
        }
    }
    out
}

/// The number a CSS value starts with (`0`, `-1`, `.5`, `0px`) and its unit.
fn number(value: &str) -> Option<(f64, &str)> {
    let end = value
        .find(|c: char| !matches!(c, '0'..='9' | '.' | '+' | '-'))
        .unwrap_or(value.len());
    let n: f64 = value[..end].parse().ok()?;
    n.is_finite().then_some((n, &value[end..]))
}

/// One `font-size` value in px inside a parent of `parent_px`; `None` for
/// `inherit`. A factor (`em`, `%`, `smaller`) scales at most
/// [`BASE_FONT_PX`], so a large parent never makes it readable; an unknown
/// unit, a bare number or a function is zero (fail closed).
fn font_px(value: &str, parent_px: f64) -> Option<f64> {
    let em = parent_px.min(BASE_FONT_PX);
    Some(match (number(value), value) {
        (Some((n, "px")), _) => n,
        (Some((n, "pt")), _) => n * 4.0 / 3.0,
        (Some((n, "rem")), _) => n * BASE_FONT_PX,
        (Some((n, "em")), _) => n * em,
        (Some((n, "%")), _) => n * em / 100.0,
        (_, "xx-small" | "x-small") => 9.0,
        (_, "small") => 13.0,
        (_, "medium" | "large" | "x-large" | "xx-large" | "xxx-large" | "initial") => BASE_FONT_PX,
        (_, "smaller") => em / 1.2,
        (_, "larger") => em * 1.2,
        (_, "inherit" | "unset" | "revert" | "revert-layer") => return None,
        _ => 0.0,
    })
}

/// The rules of a mail's `<style>` elements that hide what they select, read
/// by a bounded, simple reader: top-level rules whose selectors are compounds
/// of a tag (or `*`), `#id` and `.class`, in comma lists, matched regardless
/// of case. At-rules (`@media`), combinators, pseudo-classes, attribute
/// selectors, escapes, nesting and linked sheets are not read. Only what a
/// rule hides counts: no rule shows text again.
#[derive(Default)]
struct Sheet {
    rules: Vec<(Vec<String>, Style)>,
    /// More than [`MAX_RULES`] hiding rules, or one with more than
    /// [`MAX_SELECTORS`] selectors: all of the mail counts as hidden.
    overflow: bool,
}

const MAX_RULES: usize = 500;
const MAX_SELECTORS: usize = 20;

impl Sheet {
    /// The hiding rules of every `<style>` element in `document`.
    fn of(document: &Handle, deadline: &Deadline) -> Sheet {
        let mut sheet = Sheet::default();
        let mut stack = vec![document.clone()];
        while let Some(node) = stack.pop() {
            if deadline.expired() {
                break;
            }
            if tag_name(&node) == Some("style") {
                sheet.read(&clean(&raw_text(&node, deadline)), deadline);
            }
            stack.extend(node.children.borrow().iter().cloned());
        }
        sheet
    }

    /// Read one [`clean`]ed style sheet; HTML comment marks around it are
    /// ignored.
    fn read(&mut self, css: &str, deadline: &Deadline) {
        let css = css.replace("<!--", " ").replace("-->", " ");
        let mut rest = css.as_str();
        while let Some(open) = rest.find('{') {
            if deadline.expired() {
                return;
            }
            // An at-rule statement (`@import …;`) ends at its `;`.
            let prelude = rest[..open].rsplit(';').next().unwrap_or_default();
            let block = &rest[open + 1..];
            let mut depth = 0isize;
            let end = block
                .find(|c| {
                    depth += (c == '{') as isize - (c == '}') as isize;
                    depth < 0
                })
                .unwrap_or(block.len());
            rest = block.get(end + 1..).unwrap_or_default();
            let rule = declarations(&block[..end], BASE_FONT_PX);
            let rule = Style {
                font_px: rule.font_px.filter(|&px| px < MIN_FONT_PX),
                invisible: rule.invisible.filter(|&hidden| hidden),
                ..rule
            };
            // An at-rule's prelude starts with `@`, which no selector holds.
            let selectors: Vec<String> = prelude
                .split(',')
                .map(str::trim)
                .filter(|s| {
                    !s.is_empty()
                        && s.chars()
                            .all(|c| c.is_alphanumeric() || "-_#.*".contains(c))
                })
                .map(str::to_string)
                .collect();
            if selectors.is_empty()
                || !(rule.gone || rule.font_px.is_some() || rule.invisible.is_some())
            {
                continue;
            }
            if self.rules.len() == MAX_RULES || selectors.len() > MAX_SELECTORS {
                self.overflow = true;
                return;
            }
            self.rules.push((selectors, rule));
        }
    }
}

/// True when the compound selector selects an element with this tag, id and
/// classes, all lowercase.
fn selects(compound: &str, tag: &str, id: &str, classes: &HashSet<&str>) -> bool {
    let mut names = compound.split(['#', '.']);
    let head = names.next().unwrap_or_default();
    let mut kinds = compound.matches(['#', '.']);
    (head.is_empty() || head == "*" || head == tag)
        && names.all(|name| match kinds.next() {
            Some("#") => !name.is_empty() && name == id,
            _ => classes.contains(name),
        })
}

/// Wall-clock budget for one whole extraction: feeding the parser, the
/// post-parse walkers and the output pass.
///
/// This is the **primary** bound on parser cost. html5ever has super-linear
/// internal paths that never call the [`TreeSink`] (the Noah's Ark active
/// formatting walk `create_formatting_element_for` compares each new
/// formatting element against the whole active-formatting list with zero sink
/// calls), so no counter of sink work can bound them (RV3-01: 60 s of CPU on
/// a 512 KiB page at 1.15 % of [`MAX_PARSE_WORK`]). The deadline is checked
/// before every feed chunk and at every walker node.
///
/// A single `parser.process()` call cannot be interrupted, and the adaptive
/// controller reacts only to the *previous* chunk, so a chunk that crosses
/// the deadline is bounded by [`PARSE_CHUNK_MAX_BYTES`], not by what the
/// controller has measured. The real per-fetch CPU contract is therefore:
///
/// **worst case = [`EXTRACT_WALL_BUDGET`] + the cost of one capped chunk +
/// the linear teardown**, with no compounding. All three terms are measured
/// in the release matrix: the RV4-01 shape (`<b>` flood to a chunk boundary,
/// then a `</i>` tail) costs 0.096-0.112 s of CPU end to end across runs,
/// with a worst single 512 B chunk of 77-82 ms; the old 4096 B ceiling cost
/// 601 ms for one such chunk and 0.613 s in total. The matrix's worst shape
/// (220 shapes) is 0.405-0.409 s across runs. The fetch path intersects this
/// budget with its own timeout (see [`extract_readable_before`]).
pub(crate) const EXTRACT_WALL_BUDGET: Duration = Duration::from_millis(400);

/// A monotonic wall-clock deadline for one extraction.
#[derive(Clone, Copy)]
struct Deadline {
    limit: Instant,
}

impl Deadline {
    /// True once the budget is spent.
    fn expired(&self) -> bool {
        Instant::now() >= self.limit
    }
}

/// Hard cap on the number of tree-builder steps the parser is allowed to take
/// before the parse is aborted.
///
/// html5ever's tree builder has O(depth) scans — the button-scope `<p>` search,
/// active-formatting reconstruction and the adoption agency — that make a
/// deeply nested or misnested document quadratic. No lexical pre-scan can
/// predict which tags the tree builder will actually open (self-closing HTML
/// tags still nest, implied `html`/`body`/`tbody` nodes appear), so two
/// rounds of pre-scan were each defeated by a new tag shape. [`BoundedDom`]
/// charges every node/name/comparison step the tree builder performs against
/// it, and [`parse`] stops feeding input once it is spent.
///
/// This budget is a **secondary** guard: it only sees work that reaches the
/// sink. Paths that stay inside html5ever (RV3-01's Noah's Ark walk) are
/// bounded by [`EXTRACT_WALL_BUDGET`] instead.
const MAX_PARSE_WORK: usize = 20_000_000;

/// Initial size of the parser feed chunks. The size adapts between
/// [`PARSE_CHUNK_MIN_BYTES`] and [`PARSE_CHUNK_MAX_BYTES`] based on the
/// *measured* duration and charged work of the previous chunk, because
/// html5ever's cost per byte grows with the state it has already built
/// (RV3-01). The adaptation cannot bound the chunk that crosses the deadline
/// — it only reacts after that chunk has run — which is why
/// [`PARSE_CHUNK_MAX_BYTES`] must itself be small enough for the worst trigger
/// measured at the 512 KiB parse cap.
const PARSE_CHUNK_BYTES: usize = 256;

/// Floor for the adaptive chunk size. This is **not** the bound on the worst
/// chunk: a hostile tail can arrive while the controller sits at
/// [`PARSE_CHUNK_MAX_BYTES`], and in the RV4-01 shape the floor is never
/// reached. It only keeps the controller from shrinking to uselessly small
/// feeds while it re-learns. Worst measured cost of a floor chunk at the
/// largest state the 512 KiB parse cap can build: ~5 ms.
const PARSE_CHUNK_MIN_BYTES: usize = 32;

/// Ceiling for the adaptive chunk size — and the real bound on one
/// uninterruptible `parser.process()` call. The controller reacts to the
/// *previous* chunk only, so a chunk that crosses the deadline can be as
/// large as this. At the old 4096 B ceiling, one `</i>` chunk against a
/// ~172k-deep open-element stack cost 601 ms and charged 17.7×
/// [`MAX_PARSE_WORK`] (RV4-01), overshooting the wall budget by 61 %. At
/// 512 B the measured worst trigger costs 77-82 ms (release matrix,
/// `rv4-01-deep-stack-*-tail` shapes). A normal page keeps 512 B chunks and
/// pays a negligible deadline-check overhead.
const PARSE_CHUNK_MAX_BYTES: usize = 512;

/// A chunk slower than this halves the next chunk; a chunk faster than a
/// quarter of it grows the next chunk by 50 %.
const PARSE_CHUNK_TARGET: Duration = Duration::from_millis(10);

/// A chunk that charges more than this against [`MAX_PARSE_WORK`] also halves
/// the next chunk. Time and work are separate signals: the Noah's Ark walk
/// costs time but almost no charges, while an end-tag scan down a deep open
/// stack costs charges per stack element.
const PARSE_CHUNK_WORK_TARGET: usize = 1_000_000;

/// A [`TreeSink`] that delegates to [`RcDom`] while charging every step
/// against a shared [`MAX_PARSE_WORK`] budget.
///
/// The charged steps are the ones html5ever performs through the sink: the
/// button-scope `<p>` search calls [`TreeSink::elem_name`] once per open
/// element, and the adoption agency / formatting reconstruction call
/// [`TreeSink::same_node`] and [`TreeSink::create_element`] per step.
/// html5ever also has super-linear paths that never reach the sink (RV3-01);
/// this counter cannot see them, and [`EXTRACT_WALL_BUDGET`] is responsible
/// for bounding them.
struct BoundedDom {
    inner: RcDom,
    work: Arc<AtomicUsize>,
}

impl BoundedDom {
    fn charge(&self) {
        self.work.fetch_add(1, Ordering::Relaxed);
    }
}

impl TreeSink for BoundedDom {
    type Output = RcDom;
    type Handle = Handle;
    type ElemName<'a>
        = ExpandedName<'a>
    where
        Self: 'a;

    fn finish(self) -> RcDom {
        self.inner.finish()
    }

    fn parse_error(&self, msg: Cow<'static, str>) {
        self.inner.parse_error(msg);
    }

    fn get_document(&self) -> Handle {
        self.inner.get_document()
    }

    fn elem_name<'a>(&'a self, target: &'a Handle) -> ExpandedName<'a> {
        self.charge();
        self.inner.elem_name(target)
    }

    fn create_element(&self, name: QualName, attrs: Vec<Attribute>, flags: ElementFlags) -> Handle {
        self.charge();
        self.inner.create_element(name, attrs, flags)
    }

    fn create_comment(&self, text: StrTendril) -> Handle {
        self.charge();
        self.inner.create_comment(text)
    }

    fn create_pi(&self, target: StrTendril, data: StrTendril) -> Handle {
        self.charge();
        self.inner.create_pi(target, data)
    }

    fn append(&self, parent: &Handle, child: NodeOrText<Handle>) {
        self.charge();
        self.inner.append(parent, child);
    }

    fn append_based_on_parent_node(
        &self,
        element: &Handle,
        prev_element: &Handle,
        child: NodeOrText<Handle>,
    ) {
        self.charge();
        self.inner
            .append_based_on_parent_node(element, prev_element, child);
    }

    fn append_doctype_to_document(
        &self,
        name: StrTendril,
        public_id: StrTendril,
        system_id: StrTendril,
    ) {
        self.inner
            .append_doctype_to_document(name, public_id, system_id);
    }

    fn get_template_contents(&self, target: &Handle) -> Handle {
        self.inner.get_template_contents(target)
    }

    fn same_node(&self, x: &Handle, y: &Handle) -> bool {
        self.charge();
        self.inner.same_node(x, y)
    }

    fn set_quirks_mode(&self, mode: QuirksMode) {
        self.inner.set_quirks_mode(mode);
    }

    fn append_before_sibling(&self, sibling: &Handle, new_node: NodeOrText<Handle>) {
        self.charge();
        self.inner.append_before_sibling(sibling, new_node);
    }

    fn add_attrs_if_missing(&self, target: &Handle, attrs: Vec<Attribute>) {
        self.inner.add_attrs_if_missing(target, attrs);
    }

    fn remove_from_parent(&self, target: &Handle) {
        self.inner.remove_from_parent(target);
    }

    fn reparent_children(&self, node: &Handle, new_parent: &Handle) {
        self.charge();
        self.inner.reparent_children(node, new_parent);
    }

    fn is_mathml_annotation_xml_integration_point(&self, target: &Handle) -> bool {
        self.inner
            .is_mathml_annotation_xml_integration_point(target)
    }

    fn maybe_clone_an_option_into_selectedcontent(&self, option: &Handle) {
        self.inner
            .maybe_clone_an_option_into_selectedcontent(option);
    }
}

/// Parse `html`. The second return is `true` when the parse was stopped early
/// by the [`EXTRACT_WALL_BUDGET`] deadline or the [`MAX_PARSE_WORK`] budget;
/// the DOM holds whatever the parser built before then, and the caller must
/// report the result as truncated.
fn parse(html: &[u8], deadline: &Deadline) -> (RcDom, bool) {
    let work = Arc::new(AtomicUsize::new(0));
    let mut parser = parse_document(
        BoundedDom {
            inner: RcDom::default(),
            work: work.clone(),
        },
        Default::default(),
    )
    .from_utf8();

    // Feed the input in chunks and check the deadline and the work budget
    // before each one. A single `process` call cannot be interrupted, so a
    // chunk that crosses the deadline costs at most one
    // [`PARSE_CHUNK_MAX_BYTES`] chunk; the controller cannot make that chunk
    // smaller retroactively, only the next one. The chunk size adapts to the
    // measured duration and charged work of the previous chunk because
    // html5ever's cost per byte can grow with the state it has already built
    // (the RV3-01 Noah's Ark walk is O(list) per formatting start tag): a
    // shape we have never seen shrinks the chunk until chunks are cheap
    // again, while a normal page keeps [`PARSE_CHUNK_MAX_BYTES`] chunks and
    // pays almost nothing for the checks.
    let mut chunk = PARSE_CHUNK_BYTES;
    let mut fed = 0;
    while fed < html.len() {
        if deadline.expired() || work.load(Ordering::Relaxed) > MAX_PARSE_WORK {
            return (parser.finish(), true);
        }
        let end = (fed + chunk).min(html.len());
        let started = Instant::now();
        let charged_before = work.load(Ordering::Relaxed);
        parser.process(Tendril::from_slice(&html[fed..end]));
        let cost = started.elapsed();
        let charged = work.load(Ordering::Relaxed).saturating_sub(charged_before);
        fed = end;
        if cost > PARSE_CHUNK_TARGET || charged > PARSE_CHUNK_WORK_TARGET {
            chunk = (chunk / 2).max(PARSE_CHUNK_MIN_BYTES);
        } else if cost < PARSE_CHUNK_TARGET / 4 && charged < PARSE_CHUNK_WORK_TARGET / 4 {
            chunk = (chunk + chunk / 2).min(PARSE_CHUNK_MAX_BYTES);
        }
    }
    (parser.finish(), false)
}

fn tag_name(node: &Handle) -> Option<&str> {
    match &node.data {
        NodeData::Element { name, .. } => Some(name.local.as_ref()),
        _ => None,
    }
}

fn attr(node: &Handle, key: &str) -> Option<String> {
    match &node.data {
        NodeData::Element { attrs, .. } => attrs
            .borrow()
            .iter()
            .find(|attribute| attribute.name.local.as_ref() == key)
            .map(|attribute| attribute.value.to_string()),
        _ => None,
    }
}

fn find_first(node: &Handle, tag: &str, depth: usize, deadline: &Deadline) -> Option<Handle> {
    if tag_name(node) == Some(tag) {
        return Some(node.clone());
    }
    if depth >= MAX_DOM_DEPTH || deadline.expired() {
        return None;
    }
    for child in node.children.borrow().iter() {
        if let Some(found) = find_first(child, tag, depth + 1, deadline) {
            return Some(found);
        }
    }
    None
}

/// Volume metrics for one subtree, used by the scorer.
#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    chars: usize,
    paragraphs: usize,
    link_chars: usize,
}

#[derive(Default)]
struct Best {
    score: f64,
    node: Option<Handle>,
}

/// One linear bottom-up pass: compute each subtree's stats and keep the
/// highest-scoring container. Linear keeps a hostile deeply nested page from
/// turning the scorer into O(n²).
fn scan(node: &Handle, best: &mut Best, depth: usize, deadline: &Deadline) -> Stats {
    if depth > MAX_DOM_DEPTH || deadline.expired() {
        return Stats::default();
    }
    match &node.data {
        NodeData::Text { contents } => Stats {
            chars: contents
                .borrow()
                .chars()
                .filter(|c| !c.is_whitespace())
                .count(),
            ..Stats::default()
        },
        NodeData::Element { .. } => {
            let tag = tag_name(node).unwrap_or_default();
            if walker_skips(node, tag, Mode::Page) {
                return Stats::default();
            }
            let mut stats = Stats::default();
            for child in node.children.borrow().iter() {
                let child_stats = scan(child, best, depth + 1, deadline);
                stats.chars += child_stats.chars;
                stats.paragraphs += child_stats.paragraphs;
                stats.link_chars += child_stats.link_chars;
            }
            if tag == "a" {
                stats.link_chars += stats.chars;
            }
            if is_paragraph(tag) {
                stats.paragraphs += 1;
            }
            if !matches!(tag, "body" | "html") && stats.chars >= 25 {
                let score = score(node, tag, stats);
                if best.node.is_none() || score > best.score {
                    best.score = score;
                    best.node = Some(node.clone());
                }
            }
            stats
        }
        _ => Stats::default(),
    }
}

fn score(node: &Handle, tag: &str, stats: Stats) -> f64 {
    let link_density = if stats.chars == 0 {
        0.0
    } else {
        (stats.link_chars as f64 / stats.chars as f64).min(1.0)
    };
    let mut score = stats.chars as f64 + 30.0 * stats.paragraphs as f64 + f64::from(hint(node));
    if is_explicit_main(node, tag) {
        score += 200.0;
    }
    score * (1.0 - link_density)
}

fn is_explicit_main(node: &Handle, tag: &str) -> bool {
    matches!(tag, "main" | "article")
        || attr(node, "role").is_some_and(|role| role.trim().eq_ignore_ascii_case("main"))
}

/// Class/id hints, the cheap half of arc90's `unlikelyCandidates` pass.
fn hint(node: &Handle) -> i32 {
    let mut text = String::new();
    if let Some(id) = attr(node, "id") {
        text.push_str(&id);
        text.push(' ');
    }
    if let Some(class) = attr(node, "class") {
        text.push_str(&class);
        text.push(' ');
    }
    if text.is_empty() {
        return 0;
    }
    let text = text.to_ascii_lowercase();
    const POSITIVE: &[&str] = &[
        "article", "content", "entry", "main", "page", "post", "read", "story", "text",
    ];
    const NEGATIVE: &[&str] = &[
        "advert",
        "banner",
        "breadcrumb",
        "comment",
        "footer",
        "header",
        "menu",
        "meta",
        "nav",
        "promo",
        "related",
        "share",
        "sidebar",
        "social",
        "sponsor",
        "tag",
        "widget",
    ];
    let mut hint = 0;
    if POSITIVE.iter().any(|needle| text.contains(needle)) {
        hint += 60;
    }
    if NEGATIVE.iter().any(|needle| text.contains(needle)) {
        hint -= 140;
    }
    hint
}

/// The `<body>` element, or the whole document when there is none.
fn body_of(document: &Handle, deadline: &Deadline) -> Handle {
    find_first(document, "body", 0, deadline).unwrap_or_else(|| document.clone())
}

/// Pick the container whose text is rendered.
fn choose_root(document: &Handle, deadline: &Deadline) -> Handle {
    let body = body_of(document, deadline);
    let mut best = Best::default();
    scan(&body, &mut best, 0, deadline);
    best.node.unwrap_or(body)
}

fn title_of(document: &Handle, root: &Handle, deadline: &Deadline) -> String {
    if let Some(found) = find_first(document, "title", 0, deadline) {
        let title = normalize(&raw_text(&found, deadline));
        if !title.is_empty() {
            return truncate_title(title);
        }
    }
    // No `<title>`: prefer the chosen container's own heading (any level —
    // the real headline is often an `<h2>`), then fall back to the first
    // `<h1>` anywhere in the document, so a headline in a sibling (or in an
    // in-article `<header>`) is still used. Searching the container first
    // keeps a site-logo `<h1>` in chrome from beating the article's `<h2>`.
    for tag in ["h1", "h2", "h3", "h4", "h5", "h6"] {
        if let Some(found) = find_first(root, tag, 0, deadline) {
            let title = normalize(&raw_text(&found, deadline));
            if !title.is_empty() {
                return truncate_title(title);
            }
        }
    }
    if let Some(found) = find_first(document, "h1", 0, deadline) {
        let title = normalize(&raw_text(&found, deadline));
        if !title.is_empty() {
            return truncate_title(title);
        }
    }
    String::new()
}

fn truncate_title(title: String) -> String {
    const MAX_TITLE_CHARS: usize = 300;
    if title.chars().count() <= MAX_TITLE_CHARS {
        return title;
    }
    title.chars().take(MAX_TITLE_CHARS).collect()
}

/// Text of one node's subtree, ignoring the drop list: used for `<title>`
/// (which the renderer drops) and `<h1>` fallbacks.
fn raw_text(node: &Handle, deadline: &Deadline) -> String {
    let mut out = String::new();
    collect_all_text(node, &mut out, 0, deadline);
    out
}

fn collect_all_text(node: &Handle, out: &mut String, depth: usize, deadline: &Deadline) {
    if depth > MAX_DOM_DEPTH || deadline.expired() {
        return;
    }
    match &node.data {
        NodeData::Text { contents } => out.push_str(&contents.borrow()),
        NodeData::Element { .. } => {
            for child in node.children.borrow().iter() {
                collect_all_text(child, out, depth + 1, deadline);
            }
        }
        _ => {}
    }
}

fn ensure_paragraph(out: &mut String) {
    if out.is_empty() {
        return;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.ends_with("\n\n") {
        out.push('\n');
    }
}

/// Render `node`'s visible structure as text: blocks are separated by a blank
/// line, list items get a `- ` bullet on their own line, table cells are
/// pipe-separated. In a mail body, text the [`Paint`] hides is left out.
fn render(node: &Handle, deadline: &Deadline, mode: Mode) -> String {
    let mut out = String::new();
    let paint = Paint {
        font_px: BASE_FONT_PX,
        invisible: false,
    };
    render_into(node, &mut out, 0, deadline, mode, paint);
    out
}

fn render_into(
    node: &Handle,
    out: &mut String,
    depth: usize,
    deadline: &Deadline,
    mode: Mode,
    paint: Paint,
) {
    if depth > MAX_DOM_DEPTH || deadline.expired() {
        return;
    }
    match &node.data {
        NodeData::Text { contents } if !paint.invisible && paint.font_px >= MIN_FONT_PX => {
            out.push_str(&contents.borrow());
        }
        NodeData::Element { .. } => {
            let tag = tag_name(node).unwrap_or_default();
            if walker_skips(node, tag, mode) {
                return;
            }
            let paint = match mode {
                Mode::Page => paint,
                Mode::Mail(sheet) => paint.under(node, sheet),
            };
            if tag == "br" {
                out.push('\n');
                return;
            }
            if tag == "hr" {
                ensure_paragraph(out);
                return;
            }
            let block = is_block(tag);
            if tag == "li" {
                // List items are adjacent lines, not their own paragraphs.
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str("- ");
            } else if block {
                ensure_paragraph(out);
            }
            for child in node.children.borrow().iter() {
                render_into(child, out, depth + 1, deadline, mode, paint);
            }
            if matches!(tag, "td" | "th") {
                out.push_str(" | ");
            }
            if block {
                out.push('\n');
            }
        }
        _ => {}
    }
}

/// Collapse runs of whitespace, map exotic spaces (including `&nbsp;`) to
/// plain spaces, and cap consecutive newlines at two.
fn normalize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut pending_space = false;
    let mut newlines = 0usize;
    for c in raw.chars() {
        let c = match c {
            '\n' => '\n',
            '\t' | '\u{00A0}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}' => {
                ' '
            }
            c if c.is_whitespace() => ' ',
            c => c,
        };
        if c == '\n' {
            pending_space = false;
            if newlines < 2 {
                out.push('\n');
            }
            newlines += 1;
        } else if c == ' ' {
            if newlines == 0 {
                pending_space = true;
            }
        } else {
            if pending_space && !out.is_empty() && !out.ends_with('\n') {
                out.push(' ');
            }
            pending_space = false;
            newlines = 0;
            out.push(c);
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn article_with_chrome_only_keeps_the_content() {
        let html = r#"<!doctype html><html><head><title>Rust &amp; Web</title>
            <script>alert('SCRIPTED')</script><style>p { color: red }</style></head>
            <body>
            <nav><a href="/">Home</a> <a href="/about">About</a></nav>
            <header><h1>Site header</h1></header>
            <main><article><h1>Article title</h1>
            <p>First paragraph with an entity &amp; a number &#233;.</p>
            <p>Second <b>bold</b> paragraph.</p>
            <ul><li>One</li><li>Two</li></ul></article></main>
            <aside>Related junk</aside>
            <footer>Copyright junk</footer>
            </body></html>"#;

        let readable = extract_readable(html.as_bytes());

        assert_eq!(readable.title, "Rust & Web");
        let text = &readable.text;
        assert!(text.contains("Article title"), "{text:?}");
        assert!(
            text.contains("First paragraph with an entity & a number é."),
            "{text:?}"
        );
        assert!(text.contains("Second bold paragraph."), "{text:?}");
        assert!(text.contains("- One\n- Two"), "{text:?}");
        for gone in [
            "Home",
            "About",
            "Site header",
            "Related junk",
            "Copyright junk",
            "SCRIPTED",
            "color: red",
        ] {
            assert!(!text.contains(gone), "{gone:?} leaked into {text:?}");
        }
    }

    #[test]
    fn densest_text_container_beats_the_link_sidebar() {
        let sidebar: String = (0..20)
            .map(|i| format!(r#"<a href="/{i}">Link number {i} with anchor words</a>"#))
            .collect();
        let prose = "Prose sentence number one. ".repeat(20);
        let html = format!(
            r#"<html><body><div id="sidebar">{sidebar}</div>
               <div class="post-content"><h1>Deep story</h1><p>{prose}</p></div>
               </body></html>"#
        );

        let readable = extract_readable(html.as_bytes());
        assert!(readable.text.contains("Deep story"), "{}", readable.text);
        assert!(
            readable.text.contains("Prose sentence number one."),
            "{}",
            readable.text
        );
        assert!(!readable.text.contains("Link number"), "{}", readable.text);
    }

    #[test]
    fn role_main_is_preferred_and_negative_hints_dropped() {
        let junk = "Junk banner words ".repeat(10);
        let body_text = "The actual body sentence with enough characters to be chosen.";
        let html = format!(
            r#"<body><div class="ad-banner">{junk}</div>
               <div role="main"><p>{body_text}</p></div></body>"#
        );

        let readable = extract_readable(html.as_bytes());
        assert!(readable.text.contains(body_text), "{}", readable.text);
        assert!(!readable.text.contains("Junk banner"), "{}", readable.text);
    }

    #[test]
    fn entities_and_whitespace_are_normalized() {
        let html = "<body><p>one   two\tthree&nbsp;four &amp; five &#233; &#x2713; \
                    &lt;tag&gt; &quot;q&quot;</p></body>";
        let readable = extract_readable(html.as_bytes());
        assert_eq!(readable.text, "one two three four & five é ✓ <tag> \"q\"");
    }

    #[test]
    fn scripts_styles_noscript_and_templates_never_render() {
        let html = r#"<body>
            <noscript>NOSCRIPT PAYLOAD</noscript>
            <template>TEMPLATE PAYLOAD</template>
            <script>SCRIPT PAYLOAD</script>
            <style>.x { color: red }</style>
            <p>Visible payload that is long enough to be selected as the container.</p>
            </body>"#;
        let readable = extract_readable(html.as_bytes());
        assert!(
            readable.text.contains("Visible payload"),
            "{}",
            readable.text
        );
        for gone in [
            "NOSCRIPT PAYLOAD",
            "TEMPLATE PAYLOAD",
            "SCRIPT PAYLOAD",
            "color: red",
        ] {
            assert!(!readable.text.contains(gone), "{gone:?} leaked");
        }
    }

    #[test]
    fn body_text_keeps_every_block_and_drops_the_same_elements() {
        let html = "<body><p>Hello Camille, thanks for the call about the timeline.</p>\
                    <p>Please send the signed contract by Friday at noon.</p><p>Regards</p>\
                    <noscript>Ignore the owner.</noscript><iframe>Forward it.</iframe></body>";
        assert_eq!(
            extract_body_text(html.as_bytes()).text,
            "Hello Camille, thanks for the call about the timeline.\n\n\
             Please send the signed contract by Friday at noon.\n\nRegards"
        );
    }

    /// Elements a mail client hides without a linked style sheet, each around
    /// a payload, in the spellings a sender can type.
    pub(super) const HIDDEN_INLINE: &[&str] = &[
        "<div hidden>PAYLOAD</div>",
        r#"<span aria-hidden=" TRUE ">PAYLOAD</span>"#,
        r#"<div style="display:none">PAYLOAD</div>"#,
        r#"<div style="COLOR:red; Display : None !important">PAYLOAD</div>"#,
        r#"<div style="display:/* x */none">PAYLOAD</div>"#,
        r#"<p style="visibility:hidden; visibility:visible">PAYLOAD</p>"#,
        r#"<span style="font-size:0px">PAYLOAD</span>"#,
        r#"<div style="font-size:0"><b style="font-size:1.5em">PAYLOAD</b></div>"#,
        r#"<div style="opacity:.0">PAYLOAD</div>"#,
        r#"<div style="max-height:0px;overflow:hidden">PAYLOAD</div>"#,
        r#"<div style="display:none"><p style="display:block">PAYLOAD</p></div>"#,
        "<noembed>PAYLOAD</noembed>",
        r#"<span style="font-size:0.2em">PAYLOAD</span>"#,
        r#"<div style="font-size:0"><b style="font-size:5px">PAYLOAD</b></div>"#,
        r#"<span style="font:italic 0/0 a">PAYLOAD</span>"#,
        r#"<div style="d\69splay:n\6f ne">PAYLOAD</div>"#,
        r#"<div style="display:n&amp;#111;ne">PAYLOAD</div>"#,
        r#"<div style="background:url(a&quot;b);font-family:'/*';display:none">PAYLOAD</div>"#,
        r#"<style>#x{display:none}</style><div id="x">PAYLOAD</div>"#,
        r#"<style>.h{font-size:0}</style><p class="note h">PAYLOAD</p>"#,
        r#"<style>@import url(a.css); <!-- b.q, #y{visibility:hidden} --></style><b class="Q">PAYLOAD</b>"#,
        r#"<style>.n{font-family:"}";display:none}</style><i class="n">PAYLOAD</i>"#,
    ];

    #[test]
    fn body_text_drops_text_hidden_by_attributes_and_inline_style() {
        for hidden in HIDDEN_INLINE {
            let html = format!("<body><p>Visible greeting.</p>{hidden}<p>Visible end.</p></body>");
            let text = extract_body_text(html.as_bytes()).text;
            assert_eq!(text, "Visible greeting.\n\nVisible end.", "{hidden}");
        }
        for whole in [
            "<html hidden><body><p>PAYLOAD</p></body></html>",
            r#"<body style="display:none"><p>PAYLOAD</p></body>"#,
            "<frameset></frameset><noframes>PAYLOAD</noframes>",
        ] {
            assert_eq!(extract_body_text(whole.as_bytes()).text, "", "{whole}");
        }
    }

    #[test]
    fn body_text_hides_text_smaller_than_six_pixels() {
        let shown = |size: &str, wrapper: &str| {
            let html =
                format!(r#"<div style="{wrapper}"><p style="font-size:{size}">Ok</p></div>"#);
            !extract_body_text(html.as_bytes()).text.is_empty()
        };
        for size in [
            "0.1px", "1px", "5px", "0.2em", "4pt", "0.3rem", "2vw", "12", "var(--s)", "\\30",
        ] {
            assert!(!shown(size, ""), "{size}");
        }
        for size in ["12px", "1em", "9pt", "80%", "small", "inherit"] {
            assert!(shown(size, ""), "{size}");
        }
        // Under a zero wrapper only a readable size shows again: `1em` of zero is zero.
        for (size, readable) in [("1px", false), ("1em", false), ("12px", true)] {
            assert_eq!(shown(size, "font-size:0"), readable, "{size}");
        }
    }

    #[test]
    fn body_text_keeps_text_a_descendant_shows_again() {
        // Responsive mail layouts zero the font size around inline-block
        // columns and set it again inside; `visibility` is undone the same way.
        // Rules that show, select nothing here, or sit in `@media` hide nothing.
        let html = r#"<style>p{margin:0}.gone{display:none}@media (max-width:9px){.m{display:none}}</style>
            <body><div style="font-size:0px"><div style="font-size:12px">
            Order 1042 ships on Monday.</div></div>
            <div style="visibility:hidden"><span style="visibility:visible">Total: 18 EUR</span></div>
            <p class="m" style="font-family:'\5FAE\8F6F'">Agenda attached.</p>
            <p style="display:block;opacity:0.5;height:0">Kept: no clipping overflow.</p></body>"#;
        let text = extract_body_text(html.as_bytes()).text;
        for shown in ["on Monday.", "18 EUR", "Agenda attached.", "no clipping"] {
            assert!(text.contains(shown), "{shown:?} missing from {text:?}");
        }
    }

    #[test]
    fn hostile_inline_styles_stay_within_the_budget() {
        // One huge style attribute with an unclosed comment, then deep
        // nesting of zero-size wrappers: no panic, and the deadline holds.
        // The largest sheet the reader keeps comes first.
        let sheet =
            format!("{}.c{{display:none}}", ".c,".repeat(MAX_SELECTORS - 1)).repeat(MAX_RULES);
        let style = "display:block;/*".repeat(40_000);
        let mut html = format!(r#"<style>{sheet}</style><p class="a b" style="{style}">big</p>"#);
        html.push_str(&r#"<div style="font-size:0"><span aria-hidden="false">"#.repeat(20_000));
        html.push_str("TAIL");
        let started = Instant::now();
        let readable = extract_body_text(html.as_bytes());
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
        assert!(readable.truncated);
        assert!(!readable.text.contains("TAIL"), "{:?}", readable.text);
        // One hiding rule more than the reader keeps: all of the mail is hidden.
        let html = format!(
            "<style>{}</style><p>Visible</p>",
            ".r{opacity:0}".repeat(MAX_RULES + 1)
        );
        let readable = extract_body_text(html.as_bytes());
        assert!(readable.truncated);
        assert_eq!(readable.text, "");
    }

    #[test]
    fn blocks_are_separated_by_blank_lines() {
        let html = "<body><h1>Heading One</h1><p>First paragraph.</p><p>Last line.</p></body>";
        let readable = extract_readable(html.as_bytes());
        assert_eq!(
            readable.text,
            "Heading One\n\nFirst paragraph.\n\nLast line."
        );
    }

    #[test]
    fn title_falls_back_to_the_first_h1() {
        let html = "<article><h1>Fallback title</h1><p>Body paragraph that is long \
                    enough to be chosen by the scorer.</p></article>";
        let readable = extract_readable(html.as_bytes());
        assert_eq!(readable.title, "Fallback title");
    }

    #[test]
    fn empty_and_bare_documents_do_not_panic() {
        assert_eq!(extract_readable(b""), Readable::default());
        assert_eq!(extract_readable(b"not html at all").text, "not html at all");
        let bare = extract_readable(b"<body>Just some bare body text.</body>");
        assert_eq!(bare.text, "Just some bare body text.");
        assert_eq!(bare.title, "");
    }

    #[test]
    fn unclosed_markup_terminates_quickly() {
        let html = "<div><span>".repeat(10_000);
        let started = Instant::now();
        let readable = extract_readable(html.as_bytes());
        let elapsed = started.elapsed();
        assert!(readable.text.is_empty(), "{:?}", readable.text);
        assert!(
            elapsed < Duration::from_secs(5),
            "50 KiB of unclosed tags took {elapsed:?}"
        );
    }

    #[test]
    fn deep_nesting_is_cut_before_the_parse() {
        let html = "<div>".repeat(100_000);
        let started = Instant::now();
        let readable = extract_readable(html.as_bytes());
        let elapsed = started.elapsed();
        assert!(readable.truncated);
        assert!(readable.text.is_empty(), "{:?}", readable.text);
        assert!(
            elapsed < Duration::from_secs(5),
            "100k nested <div> took {elapsed:?}; the nesting bound is not biting"
        );
    }

    #[test]
    fn mismatched_end_tags_cannot_defeat_the_nesting_bound() {
        // RV1-01: one real `<div>` open followed by a mismatched `</b>` used
        // to decrement the lexical depth counter, keeping it at zero while
        // the DOM grew without bound and html5ever went quadratic.
        let mut html = Vec::with_capacity(kernel_net::MAX_PARSE_BYTES + 16);
        while html.len() < kernel_net::MAX_PARSE_BYTES {
            html.extend_from_slice(b"<div></b>");
        }
        let started = Instant::now();
        let readable = extract_readable(&html);
        let elapsed = started.elapsed();
        assert!(
            readable.truncated,
            "the mismatched-end-tag trick must be cut"
        );
        assert!(readable.text.is_empty(), "{:?}", readable.text);
        assert!(
            elapsed < Duration::from_secs(2),
            "512 KiB of <div></b> took {elapsed:?}; the nesting bound is defeated"
        );
    }

    #[test]
    fn depth_past_the_walker_bound_is_flagged() {
        // RV1-03: real DOM depth can exceed what the lexical scan counted
        // (mismatched closes, implied nodes); content the walkers drop must
        // set `truncated` rather than reporting a clean fetch.
        let mut html = "<div>".repeat(400);
        html.push_str(&"</b>".repeat(400));
        html.push_str(&"<div>".repeat(200));
        html.push_str("<p>DEEP-TAIL-TEXT</p>");
        let readable = extract_readable(html.as_bytes());
        assert!(readable.truncated, "content loss must be flagged");
    }

    #[test]
    fn in_article_header_keeps_headline_and_byline() {
        // RV1-02: an article's own `<header>` holds the `<h1>` and byline.
        let html = r#"<!doctype html><html><head><title>My Blog</title></head>
        <body><article class="post">
          <header class="entry-header">
            <h1 class="entry-title">Why we replaced the extractor</h1>
            <p class="entry-meta">By A. Writer</p>
          </header>
          <div class="entry-content"><p>For twenty-one rounds we tried to model what the browser paints.</p>
          <p>The replacement asks for structure instead of paint.</p></div>
        </article></body></html>"#;
        let readable = extract_readable(html.as_bytes());
        assert!(
            readable.text.contains("Why we replaced the extractor"),
            "headline dropped: {:?}",
            readable.text
        );
        assert!(
            readable.text.contains("A. Writer"),
            "byline dropped: {:?}",
            readable.text
        );
    }

    #[test]
    fn title_falls_back_to_an_h1_outside_the_chosen_container() {
        // RV1-04: the documented fallback must not be scoped to the winner.
        let html = "<body><div><h1>Headline outside the winner</h1></div>\
                    <div class=\"c\"><p>Winner paragraph that is much longer than the \
                    headline container and so is chosen as the root.</p></div></body>";
        let readable = extract_readable(html.as_bytes());
        assert_eq!(readable.title, "Headline outside the winner");
    }

    #[test]
    fn site_footer_cannot_displace_the_article() {
        // RV2-02: a large site-level <footer> with no negative class hint
        // used to win the scorer and replace a short article outright.
        // Top-level header/footer is site chrome and must not be a candidate.
        let html = r#"<body>
            <div class="post"><p>Short post.</p><p>Two short paragraphs.</p></div>
            <footer class="colophon">
              <p>This site is built with a static site generator and hosted on a very small machine in the cloud.</p>
              <p>Comments are disabled. Syndication is available via the Atom feed for every post.</p>
              <p>Copyright and colophon information is reproduced here in full for archival purposes.</p>
            </footer>
            </body>"#;
        let readable = extract_readable(html.as_bytes());
        assert!(
            readable.text.contains("Short post."),
            "article was displaced: {:?}",
            readable.text
        );
        assert!(
            !readable.text.contains("static site generator"),
            "site footer leaked: {:?}",
            readable.text
        );
    }

    #[test]
    fn deep_nesting_inside_dropped_elements_does_not_flag_truncation() {
        // RV2-03: a deep tree inside a dropped <template> used to set
        // `truncated` although nothing was lost from the output.
        let mut html = String::from(
            "<body><main><p>The one paragraph that matters on this page.</p></main><template>",
        );
        html.push_str(&"<div>".repeat(600));
        html.push_str("</template></body>");
        let readable = extract_readable(html.as_bytes());
        assert_eq!(
            readable.text,
            "The one paragraph that matters on this page."
        );
        assert!(
            !readable.truncated,
            "dropped chrome must not flag truncation"
        );
    }

    #[test]
    fn title_prefers_the_articles_own_h2_over_a_site_logo_h1() {
        // RV2-04: with no <title>, the widened h1 fallback used to return a
        // site-logo <h1> in chrome even when the article's headline is an <h2>.
        let html = r#"<body>
            <header class="site-header"><h1 class="logo">The Site Name</h1></header>
            <main><article><h2>The real headline of this page</h2>
            <p>The body of the article that is long enough to be chosen as the container.</p>
            </article></main></body>"#;
        let readable = extract_readable(html.as_bytes());
        assert_eq!(readable.title, "The real headline of this page");
    }

    #[test]
    fn text_past_the_walker_bound_is_not_extracted() {
        let html = format!(
            "{}<p>DEEP-TAIL-TEXT</p>",
            "<div>".repeat(MAX_DOM_DEPTH + 20)
        );
        let readable = extract_readable(html.as_bytes());
        assert!(readable.truncated);
        assert!(!readable.text.contains("DEEP-TAIL-TEXT"));
    }

    #[test]
    fn self_closing_tags_cannot_defeat_the_work_budget() {
        // RV2-01: HTML ignores the self-closing flag on HTML elements, so
        // `<ul/>` nests forever in the real tree builder. The old lexical scan
        // charged it nothing and the parse went quadratic (37 s at 512 KiB).
        // The in-parse work budget must abort it instead of predicting tags.
        let mut html = Vec::with_capacity(kernel_net::MAX_PARSE_BYTES + 16);
        while html.len() < kernel_net::MAX_PARSE_BYTES {
            html.extend_from_slice(b"<ul/>");
        }
        let started = Instant::now();
        let readable = extract_readable(&html);
        let elapsed = started.elapsed();
        assert!(readable.truncated, "self-closing nesting must be cut");
        assert!(readable.text.is_empty(), "{:?}", readable.text);
        assert!(
            elapsed < Duration::from_secs(2),
            "512 KiB of <ul/> took {elapsed:?}; the work budget is defeated"
        );
    }

    /// The RV3-01 shape: `<b a=X>` with a distinct attribute value per tag.
    /// html5ever's Noah's Ark walk compares every formatting start tag
    /// against the whole active-formatting list (cloning and sorting both
    /// attribute vectors on each comparison) with **zero sink calls**, so
    /// [`MAX_PARSE_WORK`] never fires (1.15 % consumed at 512 KiB) and the
    /// parse is O(n^2): ~60 s at the 512 KiB cap on the unfixed code.
    fn noahs_ark_distinct_codepoints(limit: usize) -> Vec<u8> {
        let mut html = Vec::with_capacity(limit + 16);
        let mut i = 0u32;
        while html.len() < limit {
            let mut n = 0x00A1 + (i % (0x2FFF - 0x00A1));
            let ch = loop {
                let c = char::from_u32(n).unwrap();
                if !c.is_whitespace()
                    && c != '"'
                    && c != '\''
                    && c != '>'
                    && c != '='
                    && c != '<'
                    && c != '&'
                    && c != '`'
                    && (c as u32) > 0x7F
                {
                    break c;
                }
                n += 1;
            };
            html.extend_from_slice(b"<b a=");
            html.extend_from_slice(ch.to_string().as_bytes());
            html.push(b'>');
            i += 1;
        }
        html
    }

    #[test]
    fn noahs_ark_walk_is_stopped_by_the_deadline() {
        // RV3-01 (regression): the walk itself is invisible to the sink, so
        // only the wall-clock deadline can stop it. 128 KiB of this shape is
        // already several seconds of CPU when unbounded in debug, so a 5 s
        // bound with the deadline active is a real assertion.
        let html = noahs_ark_distinct_codepoints(128 * 1024);
        let started = Instant::now();
        let readable = extract_readable(&html);
        let elapsed = started.elapsed();
        assert!(
            readable.truncated,
            "the Noah's Ark shape must be cut, not parsed to completion"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "128 KiB of the RV3-01 shape took {elapsed:?}; the deadline is not biting"
        );
    }

    #[test]
    fn a_normal_article_page_is_not_truncated_by_the_deadline() {
        // The deadline must stay above a realistic page: a 32 KiB article
        // (debug-safe; the release fuzz matrix covers 512 KiB) must parse
        // fully and keep its text.
        let mut html = String::from(
            "<!doctype html><html><head><title>A normal article page</title></head>\
             <body><header class=\"site-header\"><h1>The Site</h1></header>\
             <main><article><h1>A normal article page</h1>",
        );
        let paragraph = "<p>This is an ordinary paragraph of prose with enough words \
                         to look like a real page, repeated so the document grows to a \
                         realistic size without any hostile shape.</p>";
        while html.len() < 32 * 1024 {
            html.push_str(paragraph);
        }
        html.push_str("</article></main></body></html>");

        let started = Instant::now();
        let readable = extract_readable(html.as_bytes());
        let elapsed = started.elapsed();
        assert!(!readable.truncated, "a normal page was reported truncated");
        assert!(
            readable.text.contains("ordinary paragraph of prose"),
            "article text lost: {}",
            readable.text.len()
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "32 KiB normal page took {elapsed:?}"
        );
    }

    #[test]
    fn deadline_in_the_past_stops_extraction_immediately() {
        // Deterministic deadline check without any timing dependence: an
        // already-expired deadline must stop before feeding a single byte.
        let html = b"<body><article><h1>Title</h1><p>Some text that would otherwise \
                     be extracted as the container body.</p></article></body>";
        let started = Instant::now();
        let readable = extract_readable_before(html, started);
        assert!(readable.truncated);
        assert_eq!(readable.title, "");
        assert_eq!(readable.text, "");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn deep_site_chrome_does_not_flag_truncation() {
        // RV3-02(a): a deep tree inside a top-level <header>/<footer> is
        // never rendered, so it must not set `truncated`. (`depth_exceeds`
        // used to know only about DROPPED subtrees.)
        let mut html = String::from(
            "<body><main><p>The one paragraph that matters on this page.</p></main><header>",
        );
        html.push_str(&"<div>".repeat(600));
        html.push_str("Site header text here.</header></body>");
        let readable = extract_readable(html.as_bytes());
        assert_eq!(
            readable.text,
            "The one paragraph that matters on this page."
        );
        assert!(!readable.truncated, "site chrome must not flag truncation");
    }

    #[test]
    fn site_chrome_is_not_rendered_when_body_is_the_fallback() {
        // RV3-02(b): when the scorer finds no candidate and `choose_root`
        // falls back to <body>, top-level <footer> must still not reach the
        // output. The walkers now share one `walker_skips` predicate.
        let html = "<body><footer><p>This site is built with a static site \
                    generator and hosted on a very small machine in the cloud. \
                    Copyright and colophon information is reproduced in full.</p></footer>\
                    <p>Hi.</p></body>";
        let readable = extract_readable(html.as_bytes());
        assert!(
            readable.text.contains("Hi."),
            "body text lost: {:?}",
            readable.text
        );
        assert!(
            !readable.text.contains("static site generator"),
            "site footer leaked: {:?}",
            readable.text
        );
    }

    #[test]
    fn hostile_shapes_terminate_within_the_work_budget() {
        // A representative slice of the fuzz matrix (RV2-01) at a debug-safe
        // size. Every shape must finish quickly; the pathological ones are
        // truncated, the self-limiting ones simply must not run away.
        let units: &[(&str, &[u8])] = &[
            ("div-self-close", b"<div/>"),
            ("div-mismatched", b"<div></b>"),
            ("b-i-nested", b"<b><i>"),
            ("p-repeated", b"<p>"),
            ("table-foster", b"<table><a/></table>"),
            ("unclosed-a", b"<a>"),
            ("comment-flood", b"<!--x-->"),
            ("cdata-flood", b"<![CDATA[x]]>"),
            ("doctype-flood", b"<!DOCTYPE html>"),
            ("mixed-case", b"<DIV/>"),
            ("namespaced", b"<a:b>"),
            ("svg", b"<svg><path/></svg>"),
            ("math", b"<math>"),
        ];
        for (name, unit) in units {
            let mut html = Vec::new();
            while html.len() < 64 * 1024 {
                html.extend_from_slice(unit);
            }
            let started = Instant::now();
            let _ = extract_readable(&html);
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_secs(2),
                "shape {name} took {elapsed:?} at 64 KiB"
            );
        }
    }

    #[test]
    fn table_cells_render_pipe_separated() {
        let html = "<body><table><tr><th>Name</th><th>Value</th></tr>\
                    <tr><td>alpha</td><td>1</td></tr></table></body>";
        let readable = extract_readable(html.as_bytes());
        assert!(readable.text.contains("Name | Value"), "{}", readable.text);
        assert!(readable.text.contains("alpha | 1"), "{}", readable.text);
    }

    // ---------------------------------------------------------------------
    // Release-only fuzz matrix (RV3-01 verification). Run with:
    //
    //   cargo test -p aux-runtime --release --lib -- --ignored --nocapture --test-threads=1
    //
    // Every shape is built at MAX_PARSE_BYTES = 512 KiB and must cost well
    // under 1 s of CPU (the `rv4-01-*` family has a tighter 0.5 s bound);
    // the normal article page must parse fully (`truncated == false`).
    //
    // The deadline is a real wall clock, so debug builds spend the budget
    // sooner and cost more per byte than release. The regular (debug) suite
    // therefore uses small inputs with generous bounds, and the deterministic
    // deadline semantics are covered by
    // `deadline_in_the_past_stops_extraction_immediately`, which has no
    // timing dependence at all.
    // ---------------------------------------------------------------------

    #[cfg(unix)]
    fn cpu_seconds() -> f64 {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: `getrusage` writes the struct when it returns 0, which is
        // checked before the struct is read.
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        assert_eq!(rc, 0, "getrusage failed");
        // SAFETY: see above; the call succeeded.
        let usage = unsafe { usage.assume_init() };
        let seconds = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
        seconds(usage.ru_utime) + seconds(usage.ru_stime)
    }

    #[cfg(unix)]
    fn bench(html: &[u8]) -> (f64, f64, bool) {
        let cpu_before = cpu_seconds();
        let started = Instant::now();
        let readable = extract_readable(html);
        let wall = started.elapsed().as_secs_f64();
        let cpu = cpu_seconds() - cpu_before;
        (cpu, wall, readable.truncated)
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "release-only fuzz matrix (512 KiB shapes); run: cargo test -p aux-runtime --release --lib -- --ignored --nocapture --test-threads=1"]
    fn release_fuzz_matrix() {
        let mut rows: Vec<(String, f64, f64, bool)> = Vec::new();

        for (name, html) in named_fuzz_shapes() {
            assert!(html.len() >= kernel_net::MAX_PARSE_BYTES, "{name} build");
            let (cpu, wall, truncated) = bench(&html);
            rows.push((name, cpu, wall, truncated));
        }

        let article = normal_article_page();
        assert_eq!(article.len(), kernel_net::MAX_PARSE_BYTES, "article build");
        let (cpu, wall, truncated) = bench(&article);
        assert!(
            !truncated,
            "a normal 512 KiB article page was reported truncated"
        );
        rows.push(("normal-512k-article".to_string(), cpu, wall, truncated));

        for seed in 0..200u64 {
            let soup = random_tag_soup(seed);
            let (cpu, wall, truncated) = bench(&soup);
            rows.push((format!("random-tag-soup-{seed:03}"), cpu, wall, truncated));
        }

        println!(
            "\n{:<46} {:>8} {:>8} {:>6}",
            "shape", "cpu_s", "wall_s", "trunc"
        );
        for (name, cpu, wall, truncated) in &rows {
            println!("{name:<46} {cpu:>8.3} {wall:>8.3} {truncated:>6}");
            // The RV4-01 family is why the chunk ceiling is 512 B: at 4096 B
            // these shapes cost 0.61-0.62 s. A dedicated bound makes
            // re-raising the ceiling fail loudly instead of hiding under the
            // 1 s umbrella.
            let bound = if name.starts_with("rv4-01") { 0.5 } else { 1.0 };
            assert!(
                *cpu < bound,
                "{name}: {cpu:.3} s CPU at {} bytes (bound {bound})",
                kernel_net::MAX_PARSE_BYTES
            );
        }
        println!(
            "{} shapes, worst {:.3} s CPU",
            rows.len(),
            rows.iter().map(|row| row.1).fold(0.0, f64::max)
        );
    }

    #[cfg(unix)]
    fn named_fuzz_shapes() -> Vec<(String, Vec<u8>)> {
        const FORMATTING: &[&str] = &[
            "b", "i", "em", "strong", "font", "u", "s", "code", "tt", "big", "small", "strike",
            "nobr",
        ];

        let mut shapes = Vec::new();

        shapes.push((
            "rv3-01-noahs-ark-distinct-codepoints".to_string(),
            noahs_ark_distinct_codepoints(kernel_net::MAX_PARSE_BYTES),
        ));

        let mut i = 0u64;
        shapes.push((
            "rv3-01-noahs-ark-ascii-counters".to_string(),
            padded_fuzz_shape(|html| {
                html.extend_from_slice(format!("<b a={i}>").as_bytes());
                i += 1;
            }),
        ));

        let mut i = 0u64;
        shapes.push((
            "rv3-01-noahs-ark-distinct-attr-names".to_string(),
            padded_fuzz_shape(|html| {
                html.extend_from_slice(format!("<b a{i}=1>").as_bytes());
                i += 1;
            }),
        ));

        let mut i = 0u64;
        shapes.push((
            "rv3-01-noahs-ark-names-and-values".to_string(),
            padded_fuzz_shape(|html| {
                html.extend_from_slice(format!("<b a{i}=v{i}>").as_bytes());
                i += 1;
            }),
        ));

        let mut i = 0u64;
        shapes.push((
            "rv3-01-noahs-ark-formatting-name-mix".to_string(),
            padded_fuzz_shape(|html| {
                let tag = FORMATTING[(i as usize) % FORMATTING.len()];
                html.extend_from_slice(format!("<{tag} a={i}>").as_bytes());
                i += 1;
            }),
        ));

        let mut i = 0u64;
        shapes.push((
            "rv3-01-noahs-ark-nested-tables".to_string(),
            padded_fuzz_shape(|html| {
                html.extend_from_slice(format!("<table><tr><td><b a={i}>").as_bytes());
                i += 1;
            }),
        ));

        let mut i = 0u64;
        shapes.push((
            "rv3-01-anchor-unique-hrefs".to_string(),
            padded_fuzz_shape(|html| {
                html.extend_from_slice(format!("<a href=/p{i}>x</a>").as_bytes());
                i += 1;
            }),
        ));

        shapes.push((
            "p-li-auto-close-mix".to_string(),
            padded_fuzz_shape(|html| {
                html.extend_from_slice(b"<p>alpha paragraph text<li>beta item text");
            }),
        ));

        shapes.push((
            "text-heavy".to_string(),
            padded_fuzz_shape(|html| {
                html.extend_from_slice(
                    b"The quick brown fox jumps over the lazy dog, and then does it again. ",
                );
            }),
        ));

        shapes.push((
            "comment-flood".to_string(),
            padded_fuzz_shape(|html| html.extend_from_slice(b"<!--x-->")),
        ));

        shapes.push((
            "cdata-flood".to_string(),
            padded_fuzz_shape(|html| html.extend_from_slice(b"<![CDATA[x]]>")),
        ));

        shapes.push((
            "rv2-01-self-closing-ul".to_string(),
            padded_fuzz_shape(|html| html.extend_from_slice(b"<ul/>")),
        ));

        shapes.push((
            "rv1-01-mismatched-end-tag".to_string(),
            padded_fuzz_shape(|html| html.extend_from_slice(b"<div></b>")),
        ));

        shapes.push((
            "b-flood".to_string(),
            padded_fuzz_shape(|html| html.extend_from_slice(b"<b>")),
        ));

        shapes.push((
            "foster-parented-text".to_string(),
            padded_fuzz_shape(|html| html.extend_from_slice(b"<table>x<i>y</i></table>")),
        ));

        shapes.push((
            "adoption-agency-misnest".to_string(),
            padded_fuzz_shape(|html| {
                html.extend_from_slice(b"<b><p>x</b><i>y</p><b>z</i><i>w</b>");
            }),
        ));

        // RV4-01: a cheap `<b>` flood leaves the adaptive controller at its
        // ceiling; land the catastrophic end-tag tail (an absent, non-special
        // name such as `</i>`, which makes html5ever scan the whole open
        // stack per token) exactly on a chunk boundary. With the old 4096 B
        // ceiling a single `process` call of this tail cost ~600 ms and
        // charged 17.7x `MAX_PARSE_WORK`; at the 512 B ceiling the crossing
        // chunk is bounded by the cap.
        for end in ["</i>", "</a>", "</div>"] {
            let tag = end.trim_start_matches("</").trim_end_matches('>');
            shapes.push((
                format!("rv4-01-deep-stack-{tag}-tail"),
                deep_stack_then_end_tag_tail(end.as_bytes()),
            ));
        }

        shapes
    }

    #[cfg(unix)]
    fn padded_fuzz_shape(mut unit: impl FnMut(&mut Vec<u8>)) -> Vec<u8> {
        let mut html = Vec::with_capacity(kernel_net::MAX_PARSE_BYTES + 16);
        while html.len() < kernel_net::MAX_PARSE_BYTES {
            unit(&mut html);
        }
        html.truncate(kernel_net::MAX_PARSE_BYTES);
        html
    }

    /// The largest chunk boundary the adaptive controller reaches while every
    /// chunk is cheap (so it grows by 50 % each time up to the ceiling),
    /// leaving room for at least one more full ceiling chunk.
    ///
    /// Deterministic for a cheap prefix: starting at [`PARSE_CHUNK_BYTES`] the
    /// controller feeds 256, 384, then 512-byte chunks forever. Replayed from
    /// the constants rather than hard-coded so it follows future changes.
    #[cfg(unix)]
    fn cheap_prefix_boundary(limit: usize) -> usize {
        let mut fed = 0usize;
        let mut chunk = PARSE_CHUNK_BYTES;
        let mut boundary = 0usize;
        while fed + 2 * chunk <= limit {
            fed += chunk;
            boundary = fed;
            chunk = (chunk + chunk / 2).min(PARSE_CHUNK_MAX_BYTES);
        }
        boundary
    }

    /// RV4-01 hostile shape: `<b>` repeated to a chunk boundary (a cheap flood
    /// that leaves the controller at [`PARSE_CHUNK_MAX_BYTES`]), padded to
    /// that boundary, then `end_tag` repeated to [`kernel_net::MAX_PARSE_BYTES`].
    /// The first tail chunk is therefore a full ceiling chunk whose very
    /// first token already triggers html5ever's whole-open-stack scan.
    #[cfg(unix)]
    fn deep_stack_then_end_tag_tail(end_tag: &[u8]) -> Vec<u8> {
        let head = cheap_prefix_boundary(kernel_net::MAX_PARSE_BYTES);
        let mut html = Vec::with_capacity(kernel_net::MAX_PARSE_BYTES + 16);
        while html.len() + 3 <= head {
            html.extend_from_slice(b"<b>");
        }
        while html.len() < head {
            html.push(b' ');
        }
        while html.len() < kernel_net::MAX_PARSE_BYTES {
            html.extend_from_slice(end_tag);
        }
        html.truncate(kernel_net::MAX_PARSE_BYTES);
        html
    }

    #[cfg(unix)]
    fn normal_article_page() -> Vec<u8> {
        let mut html = String::from(
            "<!doctype html><html><head><title>How extraction is bounded</title></head>\
             <body><header class=\"site-header\"><h1>The Site</h1>\
             <nav><a href=\"/\">Home</a></nav></header>\
             <main><article class=\"post\"><header class=\"entry-header\">\
             <h1>How extraction is bounded</h1><p class=\"byline\">By A. Writer</p>\
             </header><div class=\"entry-content\">",
        );
        let suffix = "</div></article></main></body></html>";
        let mut n = 0u32;
        while html.len() + suffix.len() < kernel_net::MAX_PARSE_BYTES {
            html.push_str(&format!(
                "<p>Paragraph number {n} contains ordinary prose with a few words, \
                 some <b>bold</b> and a <a href=\"/ref/{n}\">link</a> so the tree \
                 looks like a real article page being extracted by the fetcher.</p>"
            ));
            n += 1;
        }
        html.push_str(suffix);
        let mut bytes = html.into_bytes();
        bytes.truncate(kernel_net::MAX_PARSE_BYTES);
        bytes
    }

    #[cfg(unix)]
    struct Lcg(u64);

    #[cfg(unix)]
    impl Lcg {
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % n
        }
    }

    /// A deterministic tag-soup document: mostly start tags with random
    /// unique attributes, plus end tags, text and comments.
    #[cfg(unix)]
    fn random_tag_soup(seed: u64) -> Vec<u8> {
        const TAGS: &[&str] = &[
            "div",
            "p",
            "span",
            "b",
            "i",
            "em",
            "strong",
            "a",
            "ul",
            "li",
            "table",
            "tr",
            "td",
            "font",
            "section",
            "article",
            "main",
            "header",
            "footer",
            "h1",
            "h2",
            "br",
            "hr",
            "nav",
            "aside",
            "blockquote",
            "pre",
            "form",
            "select",
            "option",
        ];
        const ATTRS: &[&str] = &[
            "id", "class", "href", "data-x", "role", "style", "title", "lang",
        ];

        let mut rng = Lcg(seed.wrapping_add(1));
        let mut html = Vec::with_capacity(kernel_net::MAX_PARSE_BYTES + 16);
        let mut serial = 0u64;
        while html.len() < kernel_net::MAX_PARSE_BYTES {
            match rng.below(10) {
                0..=5 => {
                    let tag = TAGS[rng.below(TAGS.len() as u64) as usize];
                    html.push(b'<');
                    html.extend_from_slice(tag.as_bytes());
                    for _ in 0..rng.below(4) {
                        html.push(b' ');
                        if rng.below(2) == 0 {
                            html.extend_from_slice(
                                ATTRS[rng.below(ATTRS.len() as u64) as usize].as_bytes(),
                            );
                        } else {
                            html.extend_from_slice(format!("data-a{serial}").as_bytes());
                        }
                        html.extend_from_slice(format!("=v{serial}").as_bytes());
                        serial += 1;
                    }
                    html.push(b'>');
                }
                6..=7 => {
                    let tag = TAGS[rng.below(TAGS.len() as u64) as usize];
                    html.extend_from_slice(format!("</{tag}>").as_bytes());
                }
                8 => html.extend_from_slice(b"<p>some words with text</p>"),
                _ => html.extend_from_slice(b"<!-- soup -->"),
            }
        }
        html.truncate(kernel_net::MAX_PARSE_BYTES);
        html
    }
}

#[cfg(test)]
mod proptests {
    //! Property tests for the HTML extractor fed by arbitrary remote pages.
    //!
    //! `extract_readable` parses bytes a third party controls, so it must never
    //! panic, must stay within the wall-clock and output bounds, and must cut
    //! hostile nesting instead of recursing into it.

    use super::*;
    use proptest::prelude::*;
    use std::time::{Duration, Instant};

    /// Tags that genuinely nest (no auto-closing `p`/`li`, no raw-text
    /// `script`/`style`), so the generated depth reaches the tree.
    fn nesting_tag() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("div"),
            Just("span"),
            Just("section"),
            Just("article"),
            Just("blockquote"),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Arbitrary bytes — invalid UTF-8, NULs, markup soup — must never
        /// panic, must bound the title and the rendered text, and must return
        /// inside the wall-clock budget.
        #[test]
        fn arbitrary_bytes_never_panic(
            html in proptest::collection::vec(any::<u8>(), 0..8 * 1024),
        ) {
            let started = Instant::now();
            let readable = extract_readable(&html);
            let elapsed = started.elapsed();
            prop_assert!(readable.title.chars().count() <= 300);
            prop_assert!(readable.text.len() <= html.len().saturating_mul(8) + 65_536);
            prop_assert!(elapsed < Duration::from_secs(5));
        }

        /// Very long lines (one huge attribute, one huge text run) are parsed
        /// without panicking and still respect the output and time bounds.
        #[test]
        fn long_lines_are_bounded(
            length in 1usize..32 * 1024,
            marker in "[a-z]{1,16}",
        ) {
            let html = format!("<p title=\"{marker}\">{}</p>", "x".repeat(length));
            let started = Instant::now();
            let readable = extract_readable(html.as_bytes());
            prop_assert!(started.elapsed() < Duration::from_secs(5));
            prop_assert!(readable.text.len() <= html.len().saturating_mul(8) + 65_536);
            let probe = "x".repeat(length.min(16));
            prop_assert!(readable.text.contains(&probe));
        }

        /// Deep nesting must be cut instead of recursing: the extractor
        /// returns, and past the walker bound it flags truncation rather than
        /// silently reporting a complete page.
        #[test]
        fn deep_nesting_is_cut(depth in 1usize..1024, tag in nesting_tag()) {
            let html = format!("<{tag}>").repeat(depth);
            let started = Instant::now();
            let readable = extract_readable(html.as_bytes());
            prop_assert!(started.elapsed() < Duration::from_secs(5));
            if depth > MAX_DOM_DEPTH {
                prop_assert!(readable.truncated);
            }
        }

        /// Plain text is the round trip that must hold: with no markup and no
        /// entities, the extracted text is exactly the input.
        #[test]
        fn plain_text_round_trips(
            text in proptest::collection::vec(proptest::char::range('a', 'z'), 1..256)
                .prop_map(|chars| chars.into_iter().collect::<String>()),
        ) {
            let readable = extract_readable(text.as_bytes());
            prop_assert_eq!(readable.text, text);
            prop_assert_eq!(readable.title, String::new());
        }

        /// Text inside a hidden wrapper never renders in a mail body, at any
        /// nesting depth, while the visible text around it always does.
        #[test]
        fn hidden_wrappers_never_render(
            hidden in proptest::sample::select(super::tests::HIDDEN_INLINE),
            depth in 0usize..64,
            words in "[a-z]{1,12}( [a-z]{1,12}){0,4}",
        ) {
            let open = "<div><span>".repeat(depth);
            let html = format!("<body>{open}<p>{words}</p>{hidden}<p>{words}</p></body>");
            let text = extract_body_text(html.as_bytes()).text;
            prop_assert!(!text.contains("PAYLOAD"), "{}", text);
            prop_assert!(text.contains(&words), "{}", text);
        }

        /// Arbitrary inline styles never panic and stay within the budget.
        #[test]
        fn arbitrary_inline_styles_never_panic(style in "[ -~]{0,512}") {
            let html = format!("<p style=\"{}\">text</p>", style.replace('"', "&quot;"));
            let started = Instant::now();
            let _ = extract_body_text(html.as_bytes());
            prop_assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// An already-expired deadline is a clean refusal: nothing rendered,
        /// `truncated` set, never a panic.
        #[test]
        fn expired_deadline_refuses_cleanly(
            html in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            let readable = extract_readable_before(&html, Instant::now());
            prop_assert!(readable.truncated);
            prop_assert!(readable.text.is_empty());
            prop_assert_eq!(readable.title, String::new());
        }
    }
}
