//! Old-against-new evidence for the move off `markup5ever_rcdom` (PR #78):
//! on a fixed corpus of invented pages, in page and in mail mode, the
//! extractor's text and truncated flag must match digests recorded on the
//! rcdom build (main at 5d18caf: html5ever 0.39 and `markup5ever_rcdom`).
//!
//! Titles are left out on purpose: the same PR changed the title's heading
//! fallback (it no longer reads what the renderer drops), so unit tests pin
//! titles instead. The deadline is ten minutes away and every page is small,
//! so neither the clock nor the work budget cuts a run, and the digests do
//! not depend on the machine.
//!
//! To compare the two builds page by page: copy this file to
//! `crates/aux-runtime/src/fetch/readability/parity.rs` on a checkout of the
//! old build, add `#[cfg(test)] mod parity;` to the end of
//! `readability.rs`, and run on both builds
//! `cargo test -p aux-runtime --lib parity -- --ignored --nocapture`.
//! The two dumps must be the same.

use super::{extract_with_deadline, Deadline};
use std::time::{Duration, Instant};

/// Digests recorded on the rcdom build, by group and mode (`true` is mail).
const RECORDED: &[(&str, bool, u64)] = &[
    ("soup", false, 0x1557111f02c670aa),
    ("soup", true, 0x7db5035b4ad13f87),
    ("shapes", false, 0xe1ccd81316fc62d5),
    ("shapes", true, 0x6a03c243c8330c08),
    ("mail", false, 0x0b312d4b13961c50),
    ("mail", true, 0x069234f781ce1f85),
    ("pages", false, 0x2b9a66c186e6523e),
    ("pages", true, 0x2b9a66c186e6523e),
];

/// FNV-1a over 64 bits: a small digest that is the same on every build.
struct Fnv(u64);

impl Fnv {
    fn new() -> Fnv {
        Fnv(0xcbf2_9ce4_8422_2325)
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

/// The digest of one extraction: its text and its truncated flag.
fn digest(html: &[u8], mail: bool) -> u64 {
    let deadline = Deadline {
        limit: Instant::now() + Duration::from_secs(600),
    };
    let readable = extract_with_deadline(html, deadline, mail);
    let mut fnv = Fnv::new();
    fnv.write(readable.text.as_bytes());
    fnv.write(&[0, u8::from(readable.truncated)]);
    fnv.0
}

/// The digest of a group: the digests of its pages, in order.
fn group_digest(pages: &[Vec<u8>], mail: bool) -> u64 {
    let mut fnv = Fnv::new();
    for page in pages {
        fnv.write(&digest(page, mail).to_le_bytes());
    }
    fnv.0
}

/// A deterministic pseudo-random sequence (a 64-bit LCG).
struct Lcg(u64);

impl Lcg {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 33) % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

/// Tags the soup opens and closes: blocks, formatting, tables, lists,
/// headings, elements the renderer drops, and the `html`, `body` and
/// `frameset` tags that make the tree builder merge attributes or remove a
/// node. Raw-text elements come whole, from [`SNIPPETS`].
const TAGS: &[&str] = &[
    "div",
    "p",
    "span",
    "b",
    "i",
    "em",
    "strong",
    "a",
    "font",
    "nobr",
    "u",
    "ul",
    "ol",
    "li",
    "dl",
    "dt",
    "dd",
    "table",
    "caption",
    "tbody",
    "tr",
    "td",
    "th",
    "h1",
    "h2",
    "h3",
    "section",
    "article",
    "main",
    "header",
    "footer",
    "nav",
    "aside",
    "blockquote",
    "pre",
    "br",
    "hr",
    "img",
    "form",
    "button",
    "select",
    "option",
    "svg",
    "math",
    "html",
    "body",
    "frameset",
    "object",
    "figure",
    "figcaption",
    "details",
    "summary",
    "label",
    "input",
];

/// Attributes, including the ones the scorer and the mail filter read.
const ATTRS: &[&str] = &[
    "id=main",
    "class=post",
    "class=\"nav sidebar\"",
    "class=entry-content",
    "role=main",
    "href=/x",
    "title=t",
    "hidden",
    "aria-hidden=true",
    "style=\"display:none\"",
    "style=\"font-size:0\"",
    "style=\"font-size:12px\"",
    "style=\"color:red\"",
    "data-x=1",
    "lang=en",
];

const TEXTS: &[&str] = &[
    "plain words ",
    "Fish &amp; chips&nbsp;for &#233;t&eacute; ",
    "\n   \t",
    "A sentence long enough to give its container a real score. ",
    "&lt;not a tag&gt; ",
    "x",
];

/// Whole elements and other tokens the soup drops in.
const SNIPPETS: &[&str] = &[
    "<script>if (a < b) { run(); }</script>",
    "<style>.post{display:none} p{margin:0}</style>",
    "<textarea>typed <b>text</b></textarea>",
    "<noscript>Enable scripts.</noscript>",
    "<title>A late title</title>",
    "<template><p>template text</p></template>",
    "<iframe>frame text</iframe>",
    "<!DOCTYPE html>",
    "<![CDATA[data]]>",
    "<?pi data?>",
    "</>",
];

/// Tag soup of about `limit` bytes.
fn tag_soup(seed: u64, limit: usize) -> Vec<u8> {
    let mut rng = Lcg(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1));
    let mut html = Vec::with_capacity(limit + 64);
    let mut serial = 0u64;
    while html.len() < limit {
        match rng.below(16) {
            0..=6 => {
                html.push(b'<');
                html.extend_from_slice(rng.pick(TAGS).as_bytes());
                for _ in 0..rng.below(3) {
                    html.extend_from_slice(b" ");
                    if rng.below(3) == 0 {
                        html.extend_from_slice(format!("data-a{serial}=v{serial}").as_bytes());
                        serial += 1;
                    } else {
                        html.extend_from_slice(rng.pick(ATTRS).as_bytes());
                    }
                }
                html.push(b'>');
            }
            7..=9 => html.extend_from_slice(format!("</{}>", rng.pick(TAGS)).as_bytes()),
            10..=12 => html.extend_from_slice(rng.pick(TEXTS).as_bytes()),
            13 => html.extend_from_slice(rng.pick(SNIPPETS).as_bytes()),
            14 => {
                html.extend_from_slice(format!("Sentence {serial} of the soup. ").as_bytes());
                serial += 1;
            }
            _ => html.extend_from_slice(b"<!-- note -->"),
        }
    }
    html
}

/// Units the tree builder handles in odd ways, each repeated to about 4 KiB:
/// nesting, misnesting and adoption, foster parenting, attribute merges,
/// templates, selects, implied end tags and foreign content.
const SHAPES: &[&str] = &[
    "<div/>",
    "<div></b>",
    "<b><i>",
    "<p>",
    "<ul/>",
    "<a>",
    "<a href=/x>link<div>block</a>after</div>",
    "<b><p>x</b><i>y</p><b>z</i><i>w</b>",
    "<b><div>y</b></div></b>",
    "<i a=1><i a=2><i a=3><i a=4>k",
    "<nobr>n<nobr>m",
    "<table>x<i>y</i></table>",
    "<table><b>x</b><i>y</i>",
    "<table><a/></table>",
    "<table><tr><td>c<td>d</table>",
    "<p><table>t</p>q</table>",
    "<html a=1><body b=2>",
    "<template>t<div>u</div></template>",
    "<select><option>o<optgroup>g</select>",
    "<h1>x<h2>y</h1>z</h2>",
    "<form><form>f</form>",
    "<li>one<li>two<dd>three<dt>four",
    "<svg><path/><foreignObject><p>f</p></foreignObject></svg>",
    "<math><mi>m</mi><annotation-xml encoding=text/html><p>a</p></annotation-xml></math>",
    "<!--x-->",
    "<DIV/>",
    "<a:b>",
    "<p>alpha paragraph text<li>beta item text",
];

fn repeated(unit: &str, limit: usize) -> Vec<u8> {
    let mut html = Vec::with_capacity(limit + unit.len());
    while html.len() < limit {
        html.extend_from_slice(unit.as_bytes());
    }
    html
}

/// Mail bodies around text a mail client hides, and around text it shows.
const MAIL: &[&str] = &[
    "<div hidden>HIDDEN</div>",
    "<span aria-hidden=\"true\">HIDDEN</span>",
    "<div style=\"display:none\">HIDDEN</div>",
    "<p style=\"font-size:0\">HIDDEN</p>",
    "<div style=\"font-size:0\"><b style=\"font-size:14px\">SHOWN</b></div>",
    "<p style=\"opacity:0\">HIDDEN</p>",
    "<div style=\"max-height:0;overflow:hidden\">HIDDEN</div>",
    "<p style=\"visibility:hidden\"><b style=\"visibility:visible\">SHOWN</b></p>",
    "<style>.h{display:none}</style><p class=\"h\">HIDDEN</p>",
    "<style>#k{font-size:1px}</style><p id=\"k\">HIDDEN</p>",
    "<style>@media (max-width:1px){.m{display:none}}</style><p class=\"m\">SHOWN</p>",
    "<table><tr><td>Total</td><td>18 EUR</td></tr></table>",
    "<ul><li>First item<li>Second item</ul>",
    "<blockquote>Quoted reply<br>on two lines</blockquote>",
    "<div style=\"display:none\"><p style=\"display:block\">HIDDEN</p></div>",
    "<noscript>HIDDEN</noscript><iframe>HIDDEN</iframe>",
];

/// Whole pages: an article with site chrome, a misnested and fostered page,
/// a table and list page, and a long article.
fn pages() -> Vec<Vec<u8>> {
    let chrome = "<!doctype html><html><head><title>Site</title></head><body>\
        <header class=\"site-header\"><h1>The Site</h1><nav><a href=/>Home</a></nav></header>\
        <main><article class=\"post\"><header><h1>The headline</h1><p class=byline>By A. Writer</p>\
        </header><div class=\"entry-content\"><p>First paragraph of the article.</p>\
        <p>Second <b>bold</b> and <a href=/r>linked</a> paragraph.</p></div>\
        <footer>Tags: one, two</footer></article></main>\
        <aside>Related links</aside><footer>Copyright</footer></body></html>";
    let malformed = "<html><head><title>Odd page</title></head><body><main>\
        <p>One <b>bold <i>both</b> italic</i> plain.</p><b>Bold<p>split</b> tail</p>\
        <table>a<!--c-->b<tr><td>cell one<td>cell two</tr>Fostered <i>italic</i> text\
        <tr><td>row two</td></table><a href=/x>link <div>inside</a> after</div>\
        <p>Unclosed<p>Second<ul><li>item one<li>item two</ul><body data-late=1>\
        <h2>Heading <span>with span</span></h2><p>Last words.</main></body></html>";
    let tables = "<body><h2>Prices</h2><table><thead><tr><th>Item<th>Price\
        <tbody><tr><td>Tea<td>3<tr><td>Cake<td>5</table>\
        <dl><dt>Term<dd>Definition</dl><ol><li>Step one<li>Step two</ol>\
        <pre>  keep   these\n  spaces</pre></body>";
    let mut long =
        String::from("<!doctype html><html><head><title>Long</title></head><body><main><article>");
    let mut n = 0u32;
    while long.len() < 24 * 1024 {
        long.push_str(&format!(
            "<p>Paragraph {n} has <b>bold</b>, <i>italic</i> and a \
             <a href=\"/r/{n}\">link</a> in ordinary prose.</p>"
        ));
        n += 1;
    }
    long.push_str("</article></main></body></html>");
    vec![
        chrome.as_bytes().to_vec(),
        malformed.as_bytes().to_vec(),
        tables.as_bytes().to_vec(),
        long.into_bytes(),
    ]
}

/// The corpus, by group.
fn corpus() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    vec![
        ("soup", (0..96).map(|seed| tag_soup(seed, 4096)).collect()),
        (
            "shapes",
            SHAPES.iter().map(|unit| repeated(unit, 4096)).collect(),
        ),
        (
            "mail",
            MAIL.iter()
                .map(|body| {
                    format!("<body><p>Visible greeting.</p>{body}<p>Visible end.</p></body>")
                        .into_bytes()
                })
                .collect(),
        ),
        ("pages", pages()),
    ]
}

#[test]
fn extraction_matches_the_rcdom_build() {
    let mut differs = Vec::new();
    for (group, pages) in corpus() {
        for mail in [false, true] {
            let got = group_digest(&pages, mail);
            let recorded = RECORDED
                .iter()
                .find(|(name, in_mail, _)| *name == group && *in_mail == mail)
                .map(|row| row.2);
            if recorded != Some(got) {
                differs.push(format!("(\"{group}\", {mail}, {got:#018x})"));
            }
        }
    }
    assert!(
        differs.is_empty(),
        "not what the rcdom build returned: {differs:?}; run `dump_digests` on both builds \
         to find the page"
    );
}

#[test]
#[ignore = "prints every page's digest, to compare two builds"]
fn dump_digests() {
    for (group, pages) in corpus() {
        for mail in [false, true] {
            for (index, page) in pages.iter().enumerate() {
                println!("{group} {index} mail={mail} {:#018x}", digest(page, mail));
            }
            println!(
                "(\"{group}\", {mail}, {:#018x}),",
                group_digest(&pages, mail)
            );
        }
    }
}
