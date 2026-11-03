//! Seals P2-1(d) and P3-1: text guards over `crates/kernel-privacy/src` that
//! stop [`SafeText`] and [`SafeValue`] from being minted without a grant.
//!
//! The P2-1 seal found `SafeText::__from_literal`, a `pub fn` taking a
//! `&'static str` (exactly what `Box::leak`, `OnceLock` and `LazyLock`
//! produce) and returning a `SafeText` tagged `NameCoverage::AppAuthored`. The
//! P3-1 seal found the guard too narrow: it read only `-> Self` and `-> SafeText`
//! (so `Result<Self, _>`, `Option<Self>` and `(Self, _)` passed), and it counted
//! any parameter that merely contained the word `Grant`, such as
//! `Option<&Grant>`. Each shape now has a test. They run on every `cargo test`,
//! next to the `compile_fail` doctests that pin the exact names.
//!
//! # What is checked
//!
//! * `every_public_safe_text_constructor_takes_a_grant_or_a_gate`: a `pub fn`
//!   that returns `SafeText` or `SafeValue`, or `Self` inside `impl SafeText` or
//!   `impl SafeValue`, takes a parameter of type exactly `&Grant` (or
//!   `&'a Grant`), or `&Gate` / `&mut Gate`, or, in `impl Gate`, a `self`
//!   receiver. The one exception is pinned in [`CONSUMING_COMBINATORS`].
//! * `no_trait_impl_lets_a_safe_type_mint_text`: an `impl Trait for X` where `X`
//!   names `SafeText`, `SafeValue` or `Gate` may use only the traits in
//!   [`ALLOWED_TRAITS`]. That refuses `From`, `TryFrom`, `Default`, `FromStr`,
//!   `FromIterator`, `Extend`, `Add` and `Deserialize`.
//! * `no_derive_builds_a_safe_type_from_data`: no `derive(Deserialize)` and no
//!   `derive(Default)` on `SafeText`, `SafeValue` or `Gate`.
//! * `struct_literal_sites_in_the_safe_impls_are_pinned`: the `Self {`,
//!   `SafeText {` and `SafeValue {` sites inside `impl SafeText` and
//!   `impl SafeValue` must equal [`LITERAL_SITES`].
//! * `the_removed_literal_path_is_not_reintroduced_under_its_old_name`: the
//!   round-1 names, as code shapes.
//!
//! # Limits, on purpose
//!
//! These are text scans, not type checks. A reviewer judges what they cannot
//! see:
//!
//! * a signature is read from its `pub fn` line up to its `{` or `;`, then
//!   split at `->`. A `Self` in the return type is resolved against the
//!   enclosing `impl` header;
//! * an `impl` block runs from its header to the first `}` at the header's
//!   indentation. A block with no such `}` covers no lines, so an `impl` inside
//!   a string literal cannot hide the real ones;
//! * a parameter is a grant only when its type is exactly `&Grant`. A receiver
//!   is a gate only inside `impl Gate`: a `&self` on `impl SafeText` can write
//!   the private fields, so it is not a bar;
//! * `SafeText::join` consumes text that was already checked, so it adds no raw
//!   text. It is pinned by its exact signature. Any other function with a
//!   `SafeText` parameter gets no such pass;
//! * `pub(crate)` functions are out of scope: no crate outside this one can
//!   name them. `KernelMarker` is one of them and is reviewed by hand;
//! * the literal count covers `impl SafeText` and `impl SafeValue` only.
//!   `Gate::text` and `Gate::value` build `SafeText {` and `SafeValue {` inside
//!   `impl Gate`, and a literal in a free function is not counted. A `Self {`
//!   pattern counts as a site, as a construction does;
//! * a `derive` is read from the attribute block directly above a `struct` or
//!   `enum`. Macros are not expanded, and a trait impl is read from its header;
//! * comments are removed naively, so a `//` inside a string literal truncates
//!   that line. No signature or header does that today.
//!
//! Every failure names the file, the line and the item, so a reader can judge
//! the shape instead of trusting the scan.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Traits an `impl` may add to `SafeText`, `SafeValue` or `Gate`. Each one
/// reads or compares a value that already exists; none builds text from a
/// string or from data. A new trait needs review and an entry here.
const ALLOWED_TRAITS: &[&str] = &[
    "Clone",
    "Debug",
    "Display",
    "Eq",
    "Hash",
    "PartialEq",
    "Serialize",
];

/// The types whose trait impls and derives are checked.
const SAFE_TYPES: &[&str] = &["SafeText", "SafeValue", "Gate"];

/// Struct-literal sites (`Self {`, `SafeText {`, `SafeValue {`) inside each
/// inherent `impl` of a safe value type. Today: `from_marker` and `join` in
/// `impl SafeText`, none in `impl SafeValue`. A literal skips the gate, so a new
/// one is a review point and must change this number.
const LITERAL_SITES: &[(&str, usize)] = &[("SafeText", 2), ("SafeValue", 0)];

/// Public signatures that take already-issued `SafeText` and return one. Each is
/// pinned by its exact text, so a changed signature is reviewed again.
const CONSUMING_COMBINATORS: &[&str] =
    &["pub fn join(parts: impl IntoIterator<Item = SafeText>) -> Self"];

/// One source file: its code with comments removed, and its `impl` blocks.
struct Source {
    path: PathBuf,
    code: Vec<String>,
    /// True for a line that is only a comment, so it does not end an attribute.
    comment_only: Vec<bool>,
    impls: Vec<ImplBlock>,
}

/// An `impl` block, from its header line to its closing brace (both inclusive),
/// as zero-based line indices.
struct ImplBlock {
    first: usize,
    last: usize,
    /// The last path segment of the trait, for `impl Trait for Type`.
    trait_name: Option<String>,
    /// The type after `for`, or the type after `impl` in an inherent impl.
    target: String,
}

impl ImplBlock {
    /// The type's name without generic arguments.
    fn target_name(&self) -> &str {
        self.target.split('<').next().unwrap_or_default().trim()
    }
}

/// One item the scan refuses: where it is and what it says.
#[derive(Debug)]
struct Violation {
    file: PathBuf,
    line: usize,
    item: String,
}

#[test]
fn every_public_safe_text_constructor_takes_a_grant_or_a_gate() {
    let mut violations = Vec::new();
    let (mut signatures, mut guarded, mut combinators) = (0usize, 0usize, 0usize);
    for source in sources() {
        for (index, line) in source.code.iter().enumerate() {
            if !is_public_fn(line) {
                continue;
            }
            signatures += 1;
            let signature = signature_at(&source.code, index);
            if !signature.contains("->") {
                // No return type: it returns `()`, whatever the body does.
                continue;
            }
            let Some((params, ret)) = split_signature(&signature) else {
                // A shape the scan does not understand is reported, never
                // ignored: an unparsed public `fn` returning a SafeText is
                // exactly how a grantless mint would hide.
                let item = format!("{signature} [unparsed signature]");
                violations.push(violation(&source, index, item));
                continue;
            };
            let block = innermost(&source.impls, index);
            let target = block.map(ImplBlock::target_name);
            let self_safe = matches!(target, Some("SafeText" | "SafeValue"));
            let returns_safe = has_token(ret, "SafeText")
                || has_token(ret, "SafeValue")
                || (self_safe && has_token(ret, "Self"));
            if !returns_safe {
                continue;
            }
            guarded += 1;
            if CONSUMING_COMBINATORS.contains(&signature.as_str()) {
                combinators += 1;
                continue;
            }
            let in_gate = target == Some("Gate");
            if !split_params(params)
                .iter()
                .any(|param| is_bar(param, in_gate))
            {
                violations.push(violation(&source, index, signature));
            }
        }
    }

    // The scan has teeth only if it reads the minting surface: `Gate::text`,
    // `Gate::value` and `SafeText::join` return SafeText or SafeValue.
    assert!(
        signatures > 50,
        "only {signatures} `pub fn` signatures inspected: the scan is not reading the crate"
    );
    assert!(
        guarded >= 3,
        "only {guarded} functions return SafeText or SafeValue: `Gate::text`, `Gate::value` and `SafeText::join` must be among them"
    );
    assert_eq!(
        combinators,
        CONSUMING_COMBINATORS.len(),
        "a pinned combinator was not found: its exemption no longer matches the source"
    );
    assert!(
        violations.is_empty(),
        "a public function mints SafeText/SafeValue without a &Grant or a Gate:\n{}",
        render(&violations)
    );
}

/// The exact round-1 names, as code shapes rather than prose: the doctests
/// cannot be the only regression, since a rename would leave them passing
/// against the wrong symbol.
#[test]
fn the_removed_literal_path_is_not_reintroduced_under_its_old_name() {
    let mut hits = String::new();
    for source in sources() {
        for (index, code) in source.code.iter().enumerate() {
            if code.contains("pub fn __from_literal")
                || code.contains("macro_rules! safe_text_literal")
            {
                let _ = writeln!(
                    hits,
                    "{}:{}: {}",
                    source.path.display(),
                    index + 1,
                    code.trim()
                );
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the grantless literal path is back:\n{hits}"
    );
}

/// A trait impl on `SafeText`, `SafeValue` or `Gate` must be one of
/// [`ALLOWED_TRAITS`]: `From<String>`, `Default`, `FromStr`, `Deserialize` and
/// the like each build text without a grant.
#[test]
fn no_trait_impl_lets_a_safe_type_mint_text() {
    let mut violations = Vec::new();
    let mut allowed = 0usize;
    for source in sources() {
        for block in &source.impls {
            let Some(trait_name) = &block.trait_name else {
                continue;
            };
            let Some(safe) = SAFE_TYPES
                .iter()
                .find(|&&name| has_token(&block.target, name))
            else {
                continue;
            };
            if ALLOWED_TRAITS.contains(&trait_name.as_str()) {
                allowed += 1;
                continue;
            }
            let item = format!("impl {trait_name} for {} can build a {safe}", block.target);
            violations.push(violation(&source, block.first, item));
        }
    }
    // `impl fmt::Debug for Gate` is the allowed one: it proves the trait impls
    // are read at all.
    assert!(
        allowed > 0,
        "no allowed trait impl on a safe type was seen: `impl Debug for Gate` must be among them"
    );
    assert!(
        violations.is_empty(),
        "a trait impl can mint SafeText, SafeValue or Gate without a grant:\n{}",
        render(&violations)
    );
}

/// No `derive(Deserialize)` or `derive(Default)` on a safe type: either one
/// builds it from data, not from a grant.
#[test]
fn no_derive_builds_a_safe_type_from_data() {
    let mut violations = Vec::new();
    let mut declared = BTreeSet::new();
    for source in sources() {
        // The attribute block directly above the current item. It grows over
        // every attribute line (`#[derive]` then `#[serde]`), and an item line
        // ends it.
        let mut attr = String::new();
        let mut in_attr = false;
        for (index, code) in source.code.iter().enumerate() {
            let code = code.trim();
            if in_attr || code.starts_with("#[") {
                attr.push(' ');
                attr.push_str(code);
                in_attr = !code.ends_with(']');
            } else if code.is_empty() {
                if !source.comment_only[index] {
                    attr.clear();
                }
            } else {
                if let Some(name) = declared_type(code) {
                    if let Some(&safe) = SAFE_TYPES.iter().find(|&&safe| safe == name) {
                        declared.insert(safe);
                        for derived in derives(&attr) {
                            if matches!(derived, "Default" | "Deserialize") {
                                let item = format!("#[derive({derived})] on {safe}");
                                violations.push(violation(&source, index, item));
                            }
                        }
                    }
                }
                attr.clear();
            }
        }
    }
    // Vacuity: all three safe types must have been seen with their attributes.
    assert_eq!(
        declared.len(),
        SAFE_TYPES.len(),
        "the scan found the declarations of {declared:?} only"
    );
    assert!(
        violations.is_empty(),
        "a derive builds a safe type from data:\n{}",
        render(&violations)
    );
}

/// The struct-literal sites inside `impl SafeText` and `impl SafeValue` are
/// pinned in [`LITERAL_SITES`]. A literal skips the gate's checks.
#[test]
fn struct_literal_sites_in_the_safe_impls_are_pinned() {
    let sources = sources();
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for source in &sources {
        for block in source
            .impls
            .iter()
            .filter(|block| block.trait_name.is_none())
        {
            let name = block.target_name();
            if !matches!(name, "SafeText" | "SafeValue") {
                continue;
            }
            let sites = found.entry(name.to_string()).or_default();
            for index in block.first + 1..block.last {
                let line = source.code[index].trim();
                for _ in 0..struct_literal_count(&source.code[index]) {
                    sites.push(format!("{}:{}: {line}", source.path.display(), index + 1));
                }
            }
        }
    }
    for &(name, pinned) in LITERAL_SITES {
        assert!(
            found.contains_key(name),
            "no `impl {name}` block was found: the scan cannot see the pinned type"
        );
        let sites = &found[name];
        assert_eq!(
            sites.len(),
            pinned,
            "struct-literal sites inside `impl {name}` changed from {pinned}:\n{}",
            sites.join("\n")
        );
    }
}

/// Whether one parameter (or receiver) carries the authority a mint needs: a
/// `&Grant`, a `&Gate` or `&mut Gate`, or a receiver inside `impl Gate`.
fn is_bar(param: &str, in_gate: bool) -> bool {
    let param = param.trim();
    let Some((_, ty)) = param.split_once(':') else {
        // A receiver: `self`, `&self`, `&mut self`, `mut self`.
        return in_gate && param.ends_with("self");
    };
    matches!(
        reference_to(ty.trim()),
        Some(("Grant", false) | ("Gate", _))
    )
}

/// The name a reference points at, and whether it is `&mut`: `&'a mut Gate`
/// gives `("Gate", true)`. `Option<&Grant>` is not a reference, so it is `None`.
fn reference_to(ty: &str) -> Option<(&str, bool)> {
    let rest = ty.strip_prefix('&')?.trim_start();
    let rest = match rest.strip_prefix('\'') {
        Some(after_quote) => after_quote.split_once(' ')?.1.trim_start(),
        None => rest,
    };
    Some(match rest.strip_prefix("mut ") {
        Some(name) => (name.trim(), true),
        None => (rest.trim(), false),
    })
}

/// The `impl` block that holds line `line`, the innermost one if they nest.
fn innermost(impls: &[ImplBlock], line: usize) -> Option<&ImplBlock> {
    impls
        .iter()
        .filter(|block| block.first < line && line <= block.last)
        .max_by_key(|block| block.first)
}

/// Every `impl` block of `code`, in file order.
fn impl_blocks(code: &[String]) -> Vec<ImplBlock> {
    let mut blocks = Vec::new();
    for (first, line) in code.iter().enumerate() {
        let Some(rest) = item_rest(line, "impl") else {
            continue;
        };
        // A header may wrap, so read on until the line that opens the body.
        let mut header = String::new();
        let following = code[first + 1..].iter().map(String::as_str);
        for text in std::iter::once(rest).chain(following) {
            header.push_str(text.trim());
            header.push(' ');
            if text.contains('{') {
                break;
            }
        }
        let header = header.split('{').next().unwrap_or_default();
        let header = skip_generics(header.trim());
        let header = header.split(" where ").next().unwrap_or_default().trim();
        let (trait_name, target) = match header.split_once(" for ") {
            Some((trait_part, target)) => (Some(last_segment(trait_part)), target.trim()),
            None => (None, header),
        };
        let indent = line.len() - line.trim_start().len();
        let closing = format!("{}}}", " ".repeat(indent));
        let last = code[first + 1..]
            .iter()
            .position(|text| text.trim_end() == closing)
            .map_or(first, |offset| first + 1 + offset);
        blocks.push(ImplBlock {
            first,
            last,
            trait_name,
            target: target.to_string(),
        });
    }
    blocks
}

/// The text after `keyword` when `line` starts with that item keyword.
fn item_rest<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(keyword)?;
    match rest.chars().next() {
        Some(ch) if !is_ident(ch) => Some(rest),
        _ => None,
    }
}

/// Drop a leading `<...>` generic list from an `impl` header.
fn skip_generics(header: &str) -> &str {
    let Some(inner) = header.strip_prefix('<') else {
        return header;
    };
    let mut depth = 1usize;
    for (index, ch) in inner.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return inner[index + 1..].trim_start();
                }
            }
            _ => {}
        }
    }
    header
}

/// The last path segment without generics: `fmt::Debug` is `Debug`.
fn last_segment(trait_part: &str) -> String {
    let name = trait_part.split('<').next().unwrap_or_default();
    name.rsplit("::")
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// The name of the `struct` or `enum` declared on this line, if it is one.
fn declared_type(code: &str) -> Option<&str> {
    let rest = code
        .strip_prefix("pub(crate) ")
        .or_else(|| code.strip_prefix("pub "))
        .unwrap_or(code);
    let rest = rest
        .strip_prefix("struct ")
        .or_else(|| rest.strip_prefix("enum "))?;
    rest.split(|ch: char| !is_ident(ch)).next()
}

/// The trait names in every `derive(...)` of an attribute block.
fn derives(attr: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = attr;
    while let Some(at) = rest.find("derive(") {
        let after = &rest[at + "derive(".len()..];
        let inner = after.split(')').next().unwrap_or_default();
        names.extend(
            inner
                .split(',')
                .map(|name| name.rsplit("::").next().unwrap_or_default().trim()),
        );
        rest = after;
    }
    names
}

/// Struct-literal sites on one line: `Self {`, `SafeText {` or `SafeValue {`
/// not preceded by an identifier. A return type `-> Self {` opens a body, so it
/// is not a literal.
fn struct_literal_count(line: &str) -> usize {
    let line = line
        .replace("-> Self {", "-> Self")
        .replace("-> SafeText {", "-> SafeText")
        .replace("-> SafeValue {", "-> SafeValue");
    ["Self", "SafeText", "SafeValue"]
        .into_iter()
        .map(|name| {
            line.match_indices(name)
                .filter(|&(at, _)| {
                    let before = line[..at].chars().next_back();
                    !before.is_some_and(is_ident) && line[at + name.len()..].starts_with(" {")
                })
                .count()
        })
        .sum()
}

/// Whether `token` occurs in `text` as a whole identifier.
fn has_token(text: &str, token: &str) -> bool {
    text.match_indices(token).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + token.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

fn is_ident(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// Every top-level parameter of a parameter list, split at commas outside
/// brackets and generics.
fn split_params(params: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (index, ch) in params.char_indices() {
        match ch {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&params[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&params[start..]);
    parts.retain(|part| !part.trim().is_empty());
    parts
}

/// The signature that starts at `start`: its lines joined up to the `{` or `;`.
fn signature_at(code: &[String], start: usize) -> String {
    let mut joined = String::new();
    for line in &code[start..] {
        joined.push_str(line.trim());
        joined.push(' ');
        if line.contains('{') || line.contains(';') {
            break;
        }
    }
    joined
        .split(['{', ';'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Load every `.rs` file under `src`, with comments removed and impls found.
fn sources() -> Vec<Source> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    collect_rs(&src, &mut paths);
    assert!(
        paths.len() > 10,
        "the scan found only {} files under {}: it would be vacuous",
        paths.len(),
        src.display()
    );
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).expect("a kernel-privacy source file is UTF-8");
            let code: Vec<String> = text.lines().map(strip_comment).collect();
            let comment_only: Vec<bool> = text
                .lines()
                .zip(&code)
                .map(|(raw, code)| code.trim().is_empty() && raw.trim().starts_with("//"))
                .collect();
            let impls = impl_blocks(&code);
            Source {
                path,
                code,
                comment_only,
                impls,
            }
        })
        .collect()
}

/// True when `line` declares a `pub fn` with one of the qualifiers this crate
/// uses. `pub(crate)`, `pub struct`, `pub use` and (stripped) comments are not
/// public functions.
fn is_public_fn(line: &str) -> bool {
    let Some(rest) = line.split_once("pub ").map(|(_, rest)| rest) else {
        return false;
    };
    let rest = rest.trim_start();
    ["", "const ", "async ", "unsafe "].iter().any(|qualifier| {
        rest.strip_prefix(qualifier)
            .is_some_and(|after| after.starts_with("fn "))
    })
}

/// `(params, return type)` of a signature, or `None` when it has no `->`.
fn split_signature(signature: &str) -> Option<(&str, &str)> {
    let open = signature.find('(')?;
    let mut depth = 0usize;
    let mut close = None;
    for (index, ch) in signature[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + index);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let params = &signature[open + 1..close];
    let after = signature[close + 1..].trim_start();
    let ret = after.strip_prefix("->")?.trim();
    Some((params, ret))
}

/// Drop a trailing `//` comment, keeping `http://`-style text intact.
fn strip_comment(line: &str) -> String {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return String::new();
    }
    match line.find("//") {
        Some(at) if !line[..at].ends_with(':') => line[..at].to_string(),
        _ => line.to_string(),
    }
}

fn violation(source: &Source, index: usize, item: String) -> Violation {
    Violation {
        file: source.path.clone(),
        line: index + 1,
        item,
    }
}

fn collect_rs(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

fn render(violations: &[Violation]) -> String {
    let mut out = String::new();
    for violation in violations {
        let _ = writeln!(
            out,
            "  {}:{}: {}",
            violation.file.display(),
            violation.line,
            violation.item
        );
    }
    out
}
