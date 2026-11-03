//! K-SECRET-TAIL-4: one linear link scanner. A secret's value runs from its
//! link to a structural end: the end of its paragraph, or in an unambiguous config
//! paragraph the end of its logical line. No end depends on a word of the value.
//! Its spans are only added to the older scans' spans; it never removes one.

use std::sync::LazyLock;

use regex::Regex;

use crate::contacts::fold::is_default_ignorable;

/// Fewest non-whitespace characters a value needs over its whole extent.
const FLOOR: usize = 4;
/// The link must end within this many effective bytes of the key end.
const WINDOW: usize = 96;
const LINKS: &[&str] = &[
    "is", "was", "are", "were", "est", "etait", "sont", "etaient",
];
const WEAK: &[&str] = &[
    "pass", "pw", "pin", "pins", "code", "codes", "secret", "secrets", "token", "tokens", "jeton",
    "jetons", "code pin",
];
const HEADS: &[&str] = &[
    "for", "to", "of", "on", "at", "in", "with", "from", "du", "de", "des", "pour", "sur", "au",
    "a",
];

/// Every key, on the folded text, longest alternatives first; the weak keys last.
static KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"passwords?|passwd|pwd|passphrases?|passcodes?|mots? +de +passe|mdp|code +d'acces|",
        r"code +secret|code +pin|api *key|secret +key|access +key|private +key|access +token|auth +token|",
        r"seed +phrase|recovery +phrase|jelszo|geslo|wagwoord|密码|密碼|口令|",
        r"pass|pw|pins?|codes?|secrets?|tokens?|jetons?"
    ))
    .expect("key list compiles")
});

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Empty,
    Header,
    Opener,
    Inline,
}

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Blank,
    /// Separator, value kind, key token range.
    Entry(u8, Kind, (usize, usize)),
    Structure,
    Fence,
    Other,
}

/// One physical (LF) line of the original text.
struct Line {
    start: usize,
    end: usize,
    indent: usize,
    shape: Shape,
    child: bool,
    config: bool,
    value_end: usize,
    /// End of the paragraph, including when it also looks like config.
    paragraph_end: usize,
    /// The line starts inside an owned region: it joins the logical line above.
    joined: bool,
    /// Its paragraph is Prose: a multi-line quote, a fence, an unclosed or mismatched
    /// region, or an unsure indent.
    taint: bool,
    /// The line ends a key block: its dedent is checked against the indent stack.
    ends_block: bool,
}

/// U+E000 and U+FFFD read as the letter `x` everywhere.
fn is_sentinel(ch: char) -> bool {
    matches!(ch, '\u{E000}' | '\u{FFFD}')
}

/// Byte length, with each sentinel counted as one byte (the length of `x`).
fn eff(text: &str) -> usize {
    text.len() - 2 * text.chars().filter(|&ch| is_sentinel(ch)).count()
}

fn is_mark(ch: char) -> bool {
    "*_`~\"'\u{201C}\u{201D}\u{2018}\u{2019}\u{AB}\u{BB}".contains(ch)
}

/// Push the key form of `ch`: lowercase, Latin accents gone, invisible marks dropped.
fn fold(ch: char, out: &mut String) {
    let ch = match ch {
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
        _ => ch,
    };
    let ch = match ch {
        '\u{E000}' | '\u{FFFD}' => 'x',
        '-' | '_' | '\u{A0}' | '\u{202F}' => ' ',
        '\u{2018}' | '\u{2019}' | '\u{2BC}' => '\'',
        '\u{300}'..='\u{36F}' => return,
        _ if is_default_ignorable(ch) => return,
        _ => ch,
    };
    for low in ch.to_lowercase() {
        let at = "éèêëàâóöőúüűíçčšž".chars().position(|ch| ch == low);
        out.push(at.map_or(low, |at| char::from(b"eeeeaaooouuuiccsz"[at])));
    }
}

fn is_header(value: &str) -> bool {
    value.strip_prefix(['|', '>']).is_some_and(|rest| {
        let rest = rest.trim_start_matches(|ch: char| matches!(ch, '-' | '+' | '0'..='9'));
        let rest = rest.trim_start_matches([' ', '\t']);
        rest.is_empty() || rest.starts_with('#')
    })
}

/// `^[ \t]*(- )?(export[ \t]+)?KEY[ \t]*SEP`, read at most 80 effective bytes in.
fn entry(line: &str, indent: usize, at: usize) -> Option<Shape> {
    let bytes = line.as_bytes();
    let blanks = |from: usize| {
        from + line[from..].len() - line[from..].trim_start_matches([' ', '\t']).len()
    };
    let mut i = indent + 2 * usize::from(line[indent..].starts_with("- "));
    if line[i..].starts_with("export") && matches!(bytes.get(i + 6), Some(b' ' | b'\t')) {
        i = blanks(i + 6);
    }
    let key_start = i;
    if let Some(&quote @ (b'"' | b'\'')) = bytes.get(i) {
        let close = i + 1 + line[i + 1..].find(quote as char)?;
        if !(1..=64).contains(&eff(&line[i + 1..close])) {
            return None;
        }
        i = close + 1;
    } else {
        for (n, ch) in line[i..].chars().enumerate() {
            let first = ch.is_ascii_alphabetic() || ch == '_';
            if n == 64
                || !(first
                    || is_sentinel(ch)
                    || n > 0 && (ch.is_ascii_digit() || ch == '.' || ch == '-'))
            {
                break;
            }
            i += ch.len_utf8();
        }
    }
    let key = (at + key_start, at + i);
    let rest = &line[blanks(i)..];
    let (sep, len) = match rest.as_bytes() {
        [b':', b'=', ..] => (1, 2),
        [b'=', b'>', ..] => (2, 2),
        [b'=', b'=', ..] => return None,
        [b'=', ..] => (3, 1),
        [b':'] | [b':', b' ' | b'\t' | b'\r', ..] => (4, 1),
        _ if rest.starts_with('：') => (5, 3),
        _ => return None,
    };
    let sep_end = line.len() - rest.len() + len;
    if key.0 == key.1 || eff(&line[indent..sep_end]) > 80 {
        return None;
    }
    let value = line[sep_end..].trim_matches([' ', '\t', '\r']);
    let kind = match value {
        "" => Kind::Empty,
        "[" | "{" => Kind::Opener,
        _ if is_header(value) => Kind::Header,
        _ => Kind::Inline,
    };
    Some(Shape::Entry(sep, kind, key))
}

fn shape(line: &str, at: usize) -> (usize, Shape) {
    let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
    let body = line[indent..].trim_end_matches([' ', '\t', '\r']);
    let spaces = line.len() - line.trim_start_matches(' ').len();
    let run = |fence: char| line[spaces..].chars().take_while(|&ch| ch == fence).count() >= 3;
    let shape = if body.is_empty() {
        Shape::Blank
    } else if spaces <= 3 && (run('`') || run('~')) {
        Shape::Fence
    } else if body.starts_with(['#', ';'])
        || body.starts_with("//")
        || body.starts_with('[') && body.ends_with(']')
        || body == "---"
        || body == "..."
        || body.bytes().all(|byte| b"{}[], \t".contains(&byte))
    {
        Shape::Structure
    } else {
        entry(line, indent, at).unwrap_or(Shape::Other)
    };
    (indent, shape)
}

/// The end of a key match past one plural `s`, if it passes the boundary.
fn bounded(folded: &str, start: usize, end: usize) -> Option<usize> {
    if !folded[start..end].is_ascii() {
        return Some(end);
    }
    let end = end + usize::from(folded[end..].starts_with('s'));
    let word = |ch: Option<char>| ch.is_some_and(char::is_alphanumeric);
    (!word(folded[..start].chars().next_back()) && !word(folded[end..].chars().next()))
        .then_some(end)
}

fn secret_key(token: &str) -> bool {
    let mut folded = String::new();
    token.chars().for_each(|ch| fold(ch, &mut folded));
    KEY_RE
        .find_iter(&folded)
        .any(|found| bounded(&folded, found.start(), found.end()).is_some())
}

/// Indent `a` is deeper than `b`: `b` is a strict prefix of it.
fn deeper_than(a: &str, b: &str) -> bool {
    a.len() > b.len() && a.starts_with(b)
}

/// The closers of a quote opener; empty for any other char.
fn closers(open: char) -> &'static str {
    match open {
        '"' => "\"",
        '\'' => "'",
        '”' => "”",
        '’' => "’",
        '“' => "”",
        '„' => "“”",
        '‘' => "’",
        '‚' => "‘’",
        '«' => "»",
        '»' => "«",
        '‹' => "›",
        '›' => "‹",
        '「' => "」",
        '『' => "』",
        _ => "",
    }
}

/// Opener spans by pair id (opener order), and (closer offset, id) in closer order.
type Pairs = (Vec<(usize, usize)>, Vec<(usize, usize)>);

/// The ownership pass (D2): quotes, fences, block scalars, key blocks and flow
/// regions own their lines, decided before paragraphs and modes. Each owned line is
/// marked `joined`; each closed quote or fence is recorded as a pair.
fn own(text: &str, lines: &mut [Line]) -> Pairs {
    let (mut openers, mut closes) = (Vec::new(), Vec::new());
    let (mut quotes, mut flow) = (Vec::<(char, usize)>::new(), Vec::<bool>::new());
    let (mut fence, mut scalar, mut block) = (None::<(char, usize, usize)>, None, None);
    let (mut pending, mut cand, mut rest) = (None::<usize>, None, false);
    let count = lines.len();
    for i in 0..count {
        let (start, end) = (lines[i].start, lines[i].end);
        let (raw, indent) = (&text[start..end], &text[start..lines[i].indent]);
        let spaces = raw.len() - raw.trim_start_matches(' ').len();
        let run = |ch: char| raw[spaces..].chars().take_while(|&c| c == ch).count();
        let (mut top, mut keyed, mut flow_at, quoted) = (false, false, None, !quotes.is_empty());
        if rest || quoted {
            (lines[i].joined, keyed) = (true, block.is_some());
            lines[i].taint |= quoted;
            if rest {
                continue;
            }
        } else if let Some((ch, len, id)) = fence {
            lines[i].joined = true;
            if spaces <= 3
                && run(ch) >= len
                && raw[spaces + run(ch)..]
                    .trim_matches([' ', '\t', '\r'])
                    .is_empty()
            {
                (fence, _) = (None, closes.push((start + spaces, id)));
            }
            continue;
        } else if !flow.is_empty() {
            // A flow line inside a key block stays keyed, so a value it continues is masked.
            (lines[i].joined, keyed) = (true, block.is_some());
        } else {
            for (open, kind) in [(&mut scalar, 0), (&mut block, 1)] {
                let Some(k) = *open else { continue };
                if lines[i].shape == Shape::Blank {
                    pending.get_or_insert(i);
                } else if deeper_than(indent, k) || !k.starts_with(indent) {
                    // Deeper, or unsure (tab against spaces): owned, and Prose.
                    lines[i].taint |= !deeper_than(indent, k);
                    let from = pending.take().unwrap_or(i);
                    lines[from..=i]
                        .iter_mut()
                        .for_each(|line| line.joined = true);
                    keyed = kind == 1;
                } else {
                    (*open, pending) = (None, None);
                    lines[i].ends_block |= kind == 1;
                }
                break;
            }
            if pending.is_some() {
                continue;
            }
            top = !lines[i].joined;
            if lines[i].joined && !keyed {
                continue; // block scalar text is literal
            }
        }
        if lines[i].shape == Shape::Fence && !quoted {
            let ch = raw[spaces..].chars().next().unwrap_or('`');
            fence = Some((ch, run(ch), openers.len()));
            openers.push((start + spaces, start + raw.trim_end().len()));
            lines[i].taint = true;
            continue;
        }
        if top {
            cand = None;
            if let Shape::Entry(_, kind, key) = lines[i].shape {
                let secret = secret_key(&text[key.0..key.1]);
                cand = Some((indent, secret, kind == Kind::Header));
                let value = text[key.1..end].trim_start_matches([' ', '\t']);
                let value = value[sep_len(value).unwrap_or(0)..].trim_start_matches([' ', '\t']);
                flow_at = secret.then_some(end - value.len());
            }
        }
        let (mut prev, mut escaped, mut comment) = ((i > 0).then_some('\n'), false, false);
        let mut chars = raw.char_indices().peekable();
        while let Some((at, ch)) = chars.next() {
            let next = chars
                .peek()
                .map(|&(_, ch)| if is_sentinel(ch) { 'x' } else { ch });
            let next = next.or((i + 1 < count).then_some('\n'));
            let ch = if is_sentinel(ch) { 'x' } else { ch };
            let ws = |ch: Option<char>| ch.is_none_or(char::is_whitespace);
            let ambiguous = ws(prev) && ws(next);
            let can_open = !escaped
                && !closers(ch).is_empty()
                && (!"\"'’”»›".contains(ch)
                    || !prev.is_some_and(char::is_alphanumeric) && (!ws(next) || ambiguous));
            if let Some(&(open, id)) = quotes.last() {
                let apostrophe = "'’".contains(ch);
                if !escaped
                    && !ambiguous
                    && !ws(prev)
                    && closers(open).contains(ch)
                    && !(apostrophe && next.is_some_and(char::is_alphanumeric))
                {
                    quotes.pop();
                    closes.push((start + at, id));
                } else if can_open && !ambiguous {
                    quotes.push((ch, openers.len()));
                    openers.push((start + at, start + at + ch.len_utf8()));
                } else if !escaped && "\"'”“’‘»«›‹」』".contains(ch) && !ws(prev) && !apostrophe
                {
                    rest = true;
                    break;
                }
            } else if matches!(ch, '{' | '[')
                && !comment
                && (!flow.is_empty() || keyed || flow_at == Some(start + at))
            {
                flow.push(ch == '{');
            } else if matches!(ch, '}' | ']') && !comment && !escaped && !flow.is_empty() {
                if flow.pop() != Some(ch == '}') {
                    rest = true;
                    break;
                }
            } else if !flow.is_empty() && (ch == '#' && ws(prev) || ch == '/' && next == Some('/'))
            {
                comment = true;
            } else if can_open {
                quotes.push((ch, openers.len()));
                openers.push((start + at, start + at + ch.len_utf8()));
            }
            escaped = ch == '\\' && !escaped;
            prev = Some(ch);
        }
        if !rest && quotes.is_empty() && flow.is_empty() && fence.is_none() {
            match cand.take() {
                Some((k, _, true)) => scalar = Some(k),
                Some((k, true, _)) if block.is_none() => block = Some(k),
                _ => {}
            }
        }
    }
    if rest || !quotes.is_empty() || !flow.is_empty() || fence.is_some() {
        lines[count - 1].taint = true;
    }
    (openers, closes)
}

/// Fill `value_end` for the paragraph `lines[first..=last]`.
fn close(lines: &mut [Line], first: usize, last: usize, config: bool) {
    let end = lines[last].end;
    lines[first..=last]
        .iter_mut()
        .for_each(|line| line.paragraph_end = end);
    if !config {
        lines[first..=last]
            .iter_mut()
            .for_each(|line| line.value_end = end);
        return;
    }
    // Logical lines: an Entry with its Block children, or one line.
    let mut segments: Vec<(usize, usize, bool)> = Vec::new();
    for (i, line) in lines.iter().enumerate().take(last + 1).skip(first) {
        if line.joined {
            if let Some(segment) = segments.last_mut() {
                segment.1 = i;
            }
        } else if line.child {
            while segments.last().is_some_and(|segment| segment.2) {
                segments.pop();
            }
            if let Some(segment) = segments.last_mut() {
                segment.1 = i;
            }
        } else if line.shape != Shape::Blank {
            segments.push((i, i, line.shape == Shape::Structure));
        }
    }
    // A value also takes the Structure lines right after its logical line.
    let mut run = None;
    for &(from, to, structure) in segments.iter().rev() {
        let value_end = run.unwrap_or(0).max(lines[to].end);
        for line in &mut lines[from..=to] {
            line.value_end = value_end;
            line.config = true;
        }
        run = structure.then_some(value_end);
    }
}

/// The line table, with each line's value end, and the closed pairs (Sweep 1).
fn line_table(text: &str) -> (Vec<Line>, Pairs) {
    let mut lines = Vec::new();
    let mut start = 0;
    for raw in text.split('\n') {
        let (indent, shape) = shape(raw, start);
        let (end, indent) = (start + raw.len(), start + indent);
        lines.push(Line {
            start,
            end,
            indent,
            shape,
            child: false,
            config: false,
            value_end: end,
            paragraph_end: end,
            joined: false,
            taint: false,
            ends_block: false,
        });
        start = end + 1;
    }
    let pairs = own(text, &mut lines);
    let deeper = |lines: &[Line], entry: usize, i: usize| {
        let (outer, inner) = (&lines[entry], &lines[i]);
        let (outer, inner) = (
            &text[outer.start..outer.indent],
            &text[inner.start..inner.indent],
        );
        inner.len() > outer.len() && inner.starts_with(outer)
    };
    // `owner`: the outermost Entry whose value is empty, an opener or a block header,
    // or line that ends in `:`. A blank run before a line deeper than it does not end
    // the paragraph (D-2: the residue view must not split such a block).
    let (mut first, mut blank, mut near, mut owner) = (None, None::<usize>, None, None);
    let (mut entries, mut sep0, mut prose, mut stack) = (0, 0, false, Vec::new());
    for i in 0..lines.len() {
        if lines[i].joined {
            prose |= lines[i].taint;
            continue;
        }
        if lines[i].shape == Shape::Blank {
            if first.is_some() {
                blank.get_or_insert(i);
            }
            continue;
        }
        let mut child = lines[i].shape == Shape::Other
            && near.is_some_and(|entry: usize| {
                matches!(lines[entry].shape, Shape::Entry(_, kind, _) if kind != Kind::Inline)
                    && deeper(&lines, entry, i)
            });
        if let (Some(from), Some(gap)) = (first, blank.take()) {
            if !child && !owner.is_some_and(|entry| deeper(&lines, entry, i)) {
                close(&mut lines, from, gap - 1, !prose && entries >= 2);
                first = None;
            }
        }
        if first.is_none() {
            (first, near, owner, entries, prose, child) = (Some(i), None, None, 0, false, false);
            stack.clear();
        }
        // The indent stack: a key block's end that dedents to no level is unsafe.
        let indent = &text[lines[i].start..lines[i].indent];
        let mut popped = false;
        while stack
            .last()
            .is_some_and(|top: &&str| deeper_than(top, indent))
        {
            (_, popped) = (stack.pop(), true);
        }
        prose |= lines[i].taint || lines[i].ends_block && popped && stack.last() != Some(&indent);
        if stack.last().is_none_or(|top| deeper_than(indent, top)) {
            stack.push(indent);
        }
        lines[i].child = child;
        let body = text[lines[i].start..lines[i].end].trim_end();
        let inner = owner.is_some_and(|entry| deeper(&lines, entry, i));
        if (matches!(lines[i].shape, Shape::Entry(_, kind, _) if kind != Kind::Inline)
            || body.ends_with([':', '：']))
            && !inner
        {
            owner = Some(i);
        } else if matches!(lines[i].shape, Shape::Entry(..)) && !inner {
            owner = None;
        }
        match lines[i].shape {
            Shape::Entry(sep, ..) => {
                sep0 = if entries == 0 { sep } else { sep0 };
                prose |= sep != sep0;
                entries += 1;
                near = Some(i);
            }
            Shape::Structure => {}
            _ => prose |= !child,
        }
    }
    if let Some(from) = first {
        let last = blank.map_or(lines.len() - 1, |gap| gap - 1);
        close(&mut lines, from, last, !prose && entries >= 2);
    }
    (lines, pairs)
}

fn sep_len(text: &str) -> Option<usize> {
    [":=", "=>", "->", ":", "=", "："]
        .iter()
        .find(|sep| text.starts_with(**sep))
        .map(|sep| sep.len())
}

/// After a separator, emphasis marks glued to it are skipped.
fn glued(text: &str, at: usize) -> usize {
    text.len() - text[at..].trim_start_matches(['*', '_', '`', '~']).len()
}

/// The end of the link after a key that ends at `key_end`, on the key's line.
fn link(text: &str, key_end: usize, line_end: usize) -> Option<usize> {
    let mut window = line_end;
    let mut size = 0;
    for (at, ch) in text[key_end..line_end].char_indices() {
        size += if is_sentinel(ch) { 1 } else { ch.len_utf8() };
        if size > WINDOW {
            window = key_end + at;
            break;
        }
    }
    let line = &text[..window];
    let mut at = key_end;
    for _ in 0..4 {
        match line[at..].chars().next() {
            Some(ch) if is_mark(ch) => at += ch.len_utf8(),
            _ => break,
        }
    }
    if let Some(len) = sep_len(&line[at..]) {
        return Some(glued(text, at + len));
    }
    for words in 1..=9 {
        at = window - line[at..].trim_start().len();
        let end = line[at..]
            .find(char::is_whitespace)
            .map_or(window, |len| at + len);
        if at == window
            || end == window && text[window..line_end].starts_with(|ch: char| !ch.is_whitespace())
        {
            return None;
        }
        let word = &line[at..end];
        if [":", "=", ":=", "->", "=>", "："].contains(&word) || word.ends_with([':', '=', '：'])
        {
            return Some(glued(text, end));
        }
        if word.starts_with('是') {
            return Some(at + '是'.len_utf8());
        }
        let mut folded = String::new();
        word.chars().for_each(|ch| fold(ch, &mut folded));
        let folded = folded.trim_matches(|ch: char| is_mark(ch) || ch == ' ');
        if LINKS.contains(&folded) {
            return Some(end);
        }
        if words == 1 && !HEADS.contains(&folded) || word.contains(['.', ',', ';', '!', '?']) {
            return None;
        }
        at = end;
    }
    None
}

/// A weak key counts only next to a mark, a cell pipe, or as an Entry's key.
fn weak_counts(text: &str, line: &Line, start: usize, end: usize) -> bool {
    let entry_key = matches!(line.shape, Shape::Entry(.., key) if key.0 <= start && end <= key.1);
    let before = text[line.start..start].trim_end_matches([' ', '\t']);
    let after = text[end..line.end]
        .trim_start_matches(is_mark)
        .trim_start_matches([' ', '\t']);
    entry_key
        || text[..start].chars().next_back().is_some_and(is_mark)
        || text[end..].chars().next().is_some_and(is_mark)
        || before.ends_with('|')
        || after.starts_with('|')
}

/// Split `text[from..to]` at each unescaped `|`; `cell(start, end, last)` gets each
/// cell in order and returns false to stop.
fn split(text: &str, from: usize, to: usize, mut cell: impl FnMut(usize, usize, bool) -> bool) {
    let (mut at, mut escaped) = (from, false);
    for (i, &byte) in text.as_bytes()[from..to].iter().enumerate() {
        if byte == b'|' && !escaped {
            if !cell(at, from + i, false) {
                return;
            }
            at = from + i + 1;
        }
        escaped = byte == b'\\' && !escaped;
    }
    cell(at, to, true);
}

/// The cells of a table line: the indent and one leading `|` skipped, a last
/// blank cell after a final `|` dropped.
fn row(text: &str, line: &Line, mut cell: impl FnMut(usize, usize) -> bool) {
    let from = line.indent + usize::from(text[line.indent..line.end].starts_with('|'));
    split(text, from, line.end, |start, end, last| {
        let blank = text[start..end].trim().is_empty();
        last && blank && text[..start].ends_with('|') || cell(start, end)
    });
}

/// The trimmed cell `text[start..end]`, if it has `floor` non-whitespace chars.
fn cell_value(text: &str, start: usize, end: usize, floor: usize) -> Option<(usize, usize)> {
    let cell = &text[start..end];
    let (at, trimmed) = (start + cell.len() - cell.trim_start().len(), cell.trim());
    let chars = trimmed.chars().filter(|ch| !ch.is_whitespace()).count();
    (chars >= floor).then_some((at, at + trimmed.len()))
}

/// The `|` link: a key followed (past its marks) by `|` links to the next
/// non-blank cell on its line, which ends at the next unescaped `|` or the line end.
fn pipe_value(text: &str, key_end: usize, line_end: usize) -> Option<(usize, usize)> {
    let mut at = key_end;
    for _ in 0..4 {
        match text[at..line_end].chars().next() {
            Some(ch) if is_mark(ch) => at += ch.len_utf8(),
            _ => break,
        }
    }
    let at = line_end - text[at..line_end].trim_start_matches([' ', '\t']).len();
    if !text[at..line_end].starts_with('|') {
        return None;
    }
    let mut value = None;
    split(text, at + 1, line_end, |start, end, _| {
        let blank = text[start..end].trim().is_empty();
        value = if blank {
            None
        } else {
            cell_value(text, start, end, FLOOR)
        };
        blank
    });
    value
}

/// The cell count of a valid delimiter line: every cell `[ \t]*:?-+:?[ \t]*`.
/// Whether it holds a `|` too: a pipe-free one (one cell, `---`) needs a header with
/// a `|`, so a heading rule under a plain line is no table.
fn delimiter(text: &str, line: &Line) -> Option<(usize, bool)> {
    let (mut count, mut valid) = (0, true);
    row(text, line, |start, end| {
        let cell = text[start..end].trim_matches([' ', '\t', '\r']);
        let cell = cell.strip_prefix(':').unwrap_or(cell);
        let cell = cell.strip_suffix(':').unwrap_or(cell);
        (count, valid) = (
            count + 1,
            !cell.is_empty() && cell.bytes().all(|b| b == b'-'),
        );
        valid
    });
    valid.then_some((count, text[line.start..line.end].contains('|')))
}

/// The owned lines right after each cell's line (PR1b ownership), masked whole,
/// one trimmed piece per line. A cell that masks an opener (a quote, a key, a block
/// header) ends that ownership in the residue view, which would read the lines as
/// rows. `cells` is sorted by start, so the line cursor and the result are too, and
/// each line is read once.
fn continuations(text: &str, lines: &[Line], cells: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let (mut owned, mut row, mut free) = (Vec::new(), 0, 0);
    for &(start, _) in cells {
        while lines[row].end < start {
            row += 1;
        }
        let mut next = free.max(row + 1);
        while lines.get(next).is_some_and(|line| line.joined) {
            let piece = &text[lines[next].start..lines[next].end];
            let at = lines[next].start + piece.len() - piece.trim_start().len();
            if !piece.trim().is_empty() {
                owned.push((at, at + piece.trim().len()));
            }
            next += 1;
        }
        free = next;
    }
    owned
}

/// The column form: each cell under a key column of a table outside every fence
/// and owned region. A table is a header line right above a delimiter with as many
/// cells (else no table, D5); its run of lines ends at a blank, owned or fence line.
/// Each line is read once as a delimiter, once as a header and once as a row, never
/// over the header's columns (#156 r3: a quadratic table scan). `pipes`: the
/// `|`-link values, in text order.
///
/// The gate ends each stand-in's line, so the residue view can read a table the first
/// pass did not have. Three rules keep it from finding a clear value there:
/// - a header inside a run adds its key columns to the run's: if the outer header is
///   masked away, the inner table still masks what the residue view would read;
/// - after a masked value, the rest of a row reads as a new row from column 0
///   (`after`), and a cell under a key column in either count is masked, with no
///   floor (a short cell can merge with a masked value next to it);
/// - right above a delimiter, the last `|`-link value runs to the line end, so the
///   rest of that line never reads as a header.
fn columns(
    text: &str,
    lines: &[Line],
    pipes: &mut [(usize, usize)],
    out: &mut Vec<(usize, usize)>,
) {
    let usable = |line: &Line| !line.joined && !matches!(line.shape, Shape::Blank | Shape::Fence);
    let (mut keys, mut any, mut pending, mut pipe) = (Vec::new(), false, None::<Vec<bool>>, 0);
    for (i, line) in lines.iter().enumerate() {
        if !usable(line) {
            (keys, any, pending) = (Vec::new(), false, None);
            continue;
        }
        while pipes.get(pipe).is_some_and(|value| value.0 < line.start) {
            pipe += 1;
        }
        let mut to = pipe;
        while pipes.get(to).is_some_and(|value| value.0 < line.end) {
            to += 1;
        }
        let below = lines
            .get(i + 1)
            .filter(|next| usable(next))
            .and_then(|next| delimiter(text, next));
        if below.is_some() && to > pipe {
            pipes[to - 1].1 = line.start + text[line.start..line.end].trim_end().len();
        }
        if any {
            let (mut column, mut after, mut next) = (0, 0, pipe);
            row(text, line, |start, end| {
                let key = |column: usize| keys.get(column) == Some(&true);
                let mut masked = None;
                if next < to && pipes[next].0 < end {
                    (masked, next) = (Some(pipes[next].1), next + 1);
                }
                if let Some(value) = (key(column) || key(after))
                    .then(|| cell_value(text, start, end, 1))
                    .flatten()
                {
                    (_, masked) = (out.push(value), masked.max(Some(value.1)));
                }
                after = match masked {
                    Some(at) if at <= end => {
                        usize::from(!text[at..end].trim_matches([' ', '\t']).is_empty())
                    }
                    _ => after + 1,
                };
                column += 1;
                true
            });
        }
        if let Some(header) = pending.take() {
            for (column, key) in header.into_iter().enumerate() {
                match keys.get_mut(column) {
                    Some(old) => *old |= key,
                    None => keys.push(key),
                }
                any |= key;
            }
        }
        if let Some((count, _)) =
            below.filter(|&(_, piped)| piped || text[line.start..line.end].contains('|'))
        {
            let mut header = Vec::new();
            row(text, line, |start, end| {
                header.push(secret_key(&text[start..end]));
                header.len() <= count
            });
            pending = (header.len() == count).then_some(header);
        }
    }
}

/// The value spans of every linked key in `text`, one per physical line, sorted.
/// Original offsets; `text` is read as it is (no view drops a character).
pub(crate) fn link_scan(text: &str) -> Vec<(usize, usize)> {
    scan(text, true)
}

/// `link_scan`, with the table spans of PR2 only when `tables` is set: they are
/// only added, so the spans without them are a subset (P4).
fn scan(text: &str, tables: bool) -> Vec<(usize, usize)> {
    let (mut folded, mut map, ascii) = (String::new(), Vec::new(), text.is_ascii());
    if ascii {
        let space = |byte: u8| {
            if matches!(byte, b'-' | b'_') {
                b' '
            } else {
                byte
            }
        };
        folded = text
            .bytes()
            .map(|byte| char::from(space(byte).to_ascii_lowercase()))
            .collect();
    } else {
        for (at, ch) in text.char_indices() {
            let before = folded.len();
            fold(ch, &mut folded);
            map.resize(map.len() + folded.len() - before, at);
        }
    }
    map.push(text.len());
    // Most texts hold no key: they skip the line table.
    if !KEY_RE.is_match(&folded) {
        return Vec::new();
    }
    let original = |at: usize| if ascii { at } else { map[at] };
    let (lines, (openers, closes)) = line_table(text);
    let (mut spans, mut reach, mut index, mut cells) = (Vec::new(), 0, 0, Vec::new());
    let (mut nested_tails, mut nested_reach) = (Vec::new(), 0);
    let (mut upto, mut cursor) = (vec![0; openers.len()], 0);
    let tail = text.trim_end().len();
    for found in KEY_RE.find_iter(&folded) {
        let Some(key_end) = bounded(&folded, found.start(), found.end()) else {
            continue;
        };
        let (start, end) = (original(found.start()), original(key_end));
        while lines[index].end < start {
            index += 1;
        }
        let line = &lines[index];
        let code_pin = found.as_str().starts_with("code ") && found.as_str().ends_with("pin");
        let weak = WEAK.contains(&found.as_str()) || code_pin;
        let reference_cue = (matches!(
            found.as_str(),
            "secret" | "secrets" | "token" | "tokens" | "pin" | "pins" | "jeton" | "jetons"
        ) || code_pin)
            && line.config
            && matches!(line.shape, Shape::Entry(_, _, key) if start >= key.1);
        if weak && !reference_cue && !weak_counts(text, line, start, end) {
            continue;
        }
        if tables {
            cells.extend(pipe_value(text, end, line.end));
        }
        if start < reach {
            continue;
        }
        let Some(linked) = link(text, end, line.end) else {
            continue;
        };
        // A block header (with no comment, or in config): the value is the block, not
        // `|`, which would be the residue view's value once the block is masked.
        let from = match line.shape {
            Shape::Entry(_, Kind::Header, key)
                if key.0 <= start
                    && end <= key.1
                    && (line.config || !text[linked..line.end].contains('#')) =>
            {
                line.end
            }
            _ => linked,
        };
        let value_end = line.value_end;
        reach = value_end;
        let Some(value) = text[from..value_end].find(|ch: char| !ch.is_whitespace()) else {
            continue;
        };
        let value = from + value;
        let (mut pieces, mut chars) = (Vec::new(), 0);
        for line in lines[index..]
            .iter()
            .take_while(|line| line.start < value_end)
        {
            if line.end <= value {
                continue;
            }
            let piece = &text[line.start.max(value)..line.end.min(value_end)];
            let trimmed = piece.trim();
            if !trimmed.is_empty() {
                let at = line.start.max(value) + piece.len() - piece.trim_start().len();
                pieces.push((at, at + trimmed.len()));
                chars += trimmed.chars().filter(|ch| !ch.is_whitespace()).count();
            }
        }
        if chars >= FLOOR {
            // Opener mask: an opener before the value whose closer it masks.
            let last = pieces.last().map_or(0, |piece| piece.1);
            while closes.get(cursor).is_some_and(|close| close.0 < value_end) {
                let (close, id) = closes[cursor];
                if close >= value && openers[id].0 < value && last < tail {
                    upto[id] = value;
                }
                cursor += 1;
            }
            spans.extend(pieces);
            // A prose cue inside another entry's value (e.g. `Ref: password is`)
            // can be followed by a passphrase word that looks like a config key.
            // Keep the config reading above and also mask to the paragraph end.
            if line.config
                && matches!(line.shape, Shape::Entry(_, _, key) if start >= key.1)
                && line.paragraph_end > line.value_end.max(nested_reach)
            {
                for part in lines[index + 1..]
                    .iter()
                    .take_while(|part| part.start < line.paragraph_end)
                {
                    let from = part.start.max(line.value_end).max(nested_reach);
                    if from >= part.end {
                        continue;
                    }
                    let text_part = &text[from..part.end];
                    let trimmed = text_part.trim();
                    if !trimmed.is_empty() {
                        let at = from + text_part.len() - text_part.trim_start().len();
                        nested_tails.push((at, at + trimmed.len()));
                    }
                }
                nested_reach = line.paragraph_end;
            }
        }
    }
    spans = union(spans, nested_tails);
    if tables {
        let mut table = Vec::new();
        columns(text, &lines, &mut cells, &mut table);
        cells = union(cells, table);
        let owned = continuations(text, &lines, &cells);
        cells = union(cells, owned);
    }
    if !cells.is_empty() {
        // Opener mask for a cell: a closer inside it, its opener before it.
        let mut next = 0;
        for &(close, id) in &closes {
            while cells.get(next).is_some_and(|cell| cell.1 <= close) {
                next += 1;
            }
            if let Some(&(start, end)) = cells.get(next) {
                if start <= close && openers[id].0 < start && end < tail {
                    upto[id] = upto[id].max(start);
                }
            }
        }
        spans = union(spans, cells);
    }
    // A flagged opener on an earlier line than its value (a fence, a multi-line quote)
    // is masked with every line up to the value: once the opener is masked, the
    // residue view would read that content (quotes inside a fence, a fence inside a
    // quote) as live structure.
    // Openers come in text order: one line cursor finds each opener's line, so a
    // same-line check is one comparison, not a rescan (N5: nested openers).
    let (mut extra, mut covered, mut row) = (Vec::new(), 0, 0);
    for (&(start, end), &upto) in openers.iter().zip(&upto) {
        if upto == 0 || start < covered {
            continue;
        }
        while lines[row].end < end {
            row += 1;
        }
        // The line's `\n` sits at its end; the last line has none.
        if lines[row].end >= upto {
            extra.push((start, end));
            continue;
        }
        let mut at = start;
        for part in text[start..upto].split('\n') {
            let trimmed = part.trim();
            let lead = at + part.len() - part.trim_start().len();
            if !trimmed.is_empty() {
                extra.push((lead, lead + trimmed.len()));
            }
            at += part.len() + 1;
        }
        covered = upto;
    }
    union(extra, spans)
}

/// Two runs of spans, each sorted by start, merged in one pass (D6: no sort); spans
/// that overlap or touch join.
fn union(a: Vec<(usize, usize)>, b: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    debug_assert!(a.is_sorted_by_key(|span| span.0) && b.is_sorted_by_key(|span| span.0));
    let mut merged = Vec::<(usize, usize)>::with_capacity(a.len() + b.len());
    let (mut a, mut b) = (a.into_iter().peekable(), b.into_iter().peekable());
    while let Some(span) = match (a.peek(), b.peek()) {
        (Some(x), Some(y)) if x.0 < y.0 => a.next(),
        (_, Some(_)) => b.next(),
        _ => a.next(),
    } {
        match merged.last_mut().filter(|last| span.0 <= last.1) {
            Some(last) => last.1 = last.1.max(span.1),
            None => merged.push(span),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use proptest::prelude::*;

    use super::link_scan;
    use crate::recognizer::Recognizer;
    use crate::recognizers::secrets::SecretRecognizer;

    include!("../../tests/data/secret_tail4_cases.rs");

    /// The 21 must-stay-clear pins: `link_scan` adds nothing to them.
    const CLEAR: &[&str] = &[
        "I forgot my password",
        "password reset link sent",
        "PIN code required at checkout",
        "what is a strong password?",
        "the code is on GitHub",
        "the door code is on the fridge note",
        "the token for the event is free",
        "The pass is valid until Monday.",
        "The pass to the museum is on the table.",
        "The code is clean and fast.",
        "Our team code review is on Friday.",
        "the password policy requires 12 characters",
        "mot de passe oublié ?",
        "Kérem a jelszó visszaállítását",
        "geslo je pozabljeno",
        "忘记密码了",
        "bypass: Fk3jQ9xZ2m",
        "pwd=abc",
        "The ~~password~~ hint is in the vault.",
        "The `password` field is required.",
        "The __pwd__ command prints the folder.",
    ];

    #[test]
    fn the_pins_stay_clear_and_the_link_window_is_96_effective_bytes() {
        for text in CLEAR
            .iter()
            .chain(&["|   | password |\n|---|---|\n| bank |    |"])
        {
            assert_eq!(link_scan(text), [], "{text}");
        }
        for form in ["\u{E000}", "\u{FFFD}", "x"] {
            let text = |n: usize| format!("password for {} is hunter2 horse", form.repeat(n));
            let (fits, over) = (text(88), text(89));
            assert_eq!(
                link_scan(&fits),
                [(fits.len() - 13, fits.len())],
                "B5 88 {form:?}"
            );
            assert_eq!(link_scan(&over), [], "B5 89 {form:?}");
        }
    }

    fn timed(text: &str) -> Duration {
        let start = Instant::now();
        let _ = link_scan(text);
        start.elapsed()
    }

    /// The fastest of three runs. A loaded machine or a debug build on a shared
    /// runner must not decide a bound: what is measured is the work, not the
    /// scheduler. The bound itself is unchanged.
    fn fastest(text: &str) -> Duration {
        (0..3).map(|_| timed(text)).min().unwrap_or_default()
    }

    #[test]
    fn s2_t4_and_h14_scan_in_under_a_second() {
        let n = 20_000;
        let t4 = "|".to_owned()
            + &"password|".repeat(n / 3)
            + "\n|"
            + &"---|".repeat(n / 3)
            + "\n"
            + &"x\n".repeat(n * 3);
        let s2 = " ".repeat(12_000) + &"password is \"x\" ".repeat(12_000);
        assert_eq!(link_scan(&s2), [(12_012, s2.len() - 1)]);
        for unit in ["*_*_password-_-", "mot de passe "] {
            let flood = |size: usize| unit.repeat(size / unit.len());
            let (small, big) = (fastest(&flood(10_000)), fastest(&flood(100_000)));
            assert!(big < Duration::from_secs(1), "H14 {unit:?}: {big:?}");
            assert!(
                // 10x input: linear is ~10x, quadratic ~100x. The Mac CI runner
                // measures ~13x under load, so 20x keeps a margin and still fails
                // on any quadratic path.
                big.as_secs_f64() <= 20.0 * small.as_secs_f64().max(1e-5),
                "H14 {unit:?}: {small:?} -> {big:?}"
            );
        }
        for text in [t4, s2] {
            assert!(
                fastest(&text) < Duration::from_secs(1),
                "{:?}",
                fastest(&text)
            );
        }
    }

    /// N5: balanced nested openers, all flagged by one
    /// value on their own line, scan in linear time up to 3.2 MB.
    #[test]
    fn n5_balanced_nesting_scans_in_linear_time() {
        let nested =
            |n: usize| "«“".repeat(n) + "password is red horse" + &"”»".repeat(n) + "\n\nBye";
        let (small, big) = (nested(40_000), nested(320_000));
        assert!(big.len() > 3_200_000);
        // The flagged-opener path: every opener masked, then the value.
        let value = small.find("red").unwrap_or_default();
        assert_eq!(
            link_scan(&small),
            [(0, value - "password is ".len()), (value, small.len() - 5)]
        );
        let (small, big) = (timed(&small), timed(&big));
        assert!(big < Duration::from_secs(3), "N5: {big:?}");
        assert!(
            big.as_secs_f64() <= 20.0 * small.as_secs_f64().max(1e-3),
            "N5: {small:?} -> {big:?}"
        );
    }

    /// PR2 bar: a 1 MB table (10,000 key columns, short rows) scans in linear time,
    /// under a second in a debug `link_scan` (the release gate bar is in
    /// `tests/secret_tail4.rs`). A loop over every header column for each row would walk
    /// 10,000 × 75,000 cells.
    #[test]
    fn a_megabyte_of_wide_tables_scans_in_under_a_second() {
        let text = "|".to_owned()
            + &"password|".repeat(10_000)
            + "\n|"
            + &"---|".repeat(10_000)
            + "\n"
            + &"| hunter2 |\n".repeat(75_000);
        assert!(text.len() > 1_000_000);
        assert!(link_scan(&text).len() >= 75_000);
        assert!(timed(&text) < Duration::from_secs(1), "{:?}", timed(&text));
    }

    /// P1: well-formed spans; P7: main's masked bytes are a subset of the head's.
    fn p1_and_p7(text: &str) -> Result<(), TestCaseError> {
        let spans = link_scan(text);
        for (index, &(start, end)) in spans.iter().enumerate() {
            prop_assert!(
                start < end
                    && end <= text.len()
                    && text.is_char_boundary(start)
                    && text.is_char_boundary(end)
            );
            prop_assert!(
                index == 0 || spans[index - 1].1 < start,
                "unsorted or overlapping: {spans:?}"
            );
            prop_assert!(
                !text[start..end].starts_with(char::is_whitespace)
                    && !text[start..end].ends_with(char::is_whitespace)
            );
        }
        let cover = |spans: Vec<crate::span::Span>| {
            let mut bytes = vec![false; text.len()];
            spans
                .iter()
                .for_each(|span| bytes[span.start..span.end].fill(true));
            bytes
        };
        let (main, head) = (
            cover(SecretRecognizer::main_spans(text)),
            cover(SecretRecognizer::new().analyze(text)),
        );
        prop_assert!(
            main.iter().zip(&head).all(|(main, head)| !main || *head),
            "lost a byte of main: {text:?}"
        );
        Ok(())
    }

    /// P5: every family scans in linear time, `t(2n) / t(n) ≤ 2.6` (best of 3) from
    /// 100 KB to 200 KB (plus the deep mixed-kind flow).
    #[test]
    #[ignore = "release perf ratio: cargo test --release -- --ignored"]
    fn p5_every_family_scans_in_linear_time() {
        let fill = |head: &str, unit: &str, tail: &str, size: usize| {
            head.to_owned() + &unit.repeat(size / unit.len()) + tail
        };
        let lines = |line: fn(usize) -> String, size: usize| {
            let mut text = String::new();
            for i in 0.. {
                if text.len() >= size {
                    break;
                }
                text += &line(i);
            }
            text
        };
        type Family<'a> = Box<dyn Fn(usize) -> String + 'a>;
        let families: Vec<(&str, Family<'_>)> = vec![
            (
                "T4",
                Box::new(|size| {
                    fill("|", "password|", "\n", size / 6)
                        + &fill("|", "---|", "\n", size / 6)
                        + &"x\n".repeat(size / 3)
                }),
            ),
            (
                "S2",
                Box::new(|size| fill(&" ".repeat(size / 17), "password is \"x\" ", "", size)),
            ),
            (
                "H14a",
                Box::new(|size| fill("", "*_*_password-_-", "", size)),
            ),
            ("H14b", Box::new(|size| fill("", "mot de passe ", "", size))),
            (
                "quote '",
                Box::new(|size| fill("", "password is '", "", size)),
            ),
            (
                "quote \"",
                Box::new(|size| fill("password is ", "\"", "", size)),
            ),
            (
                "quote “",
                Box::new(|size| fill("password is ", "“", "", size)),
            ),
            (
                "escape",
                Box::new(|size| fill("password is ", "\\\"", "", size)),
            ),
            ("pipe", Box::new(|size| fill("password is ", "|", "", size))),
            (
                "paragraphs",
                Box::new(|size| fill("", "password is a\n\n", "", size)),
            ),
            (
                "fences",
                Box::new(|size| fill("password is ", "```\n", "", size)),
            ),
            (
                "lists",
                Box::new(|size| fill("password is x\n", "a:\n  - b\n\n", "", size)),
            ),
            (
                "comments",
                Box::new(|size| fill("", "password: x\n# c\n", "", size)),
            ),
            (
                "unclosed",
                Box::new(|size| fill("'", "password is x\n\n", "", size)),
            ),
            (
                "indent keys",
                Box::new(|size| lines(|i| " ".repeat(i % 4096) + "password is \"x\"\n", size)),
            ),
            (
                "indent headers",
                Box::new(|size| {
                    "password is x\n".to_owned() + &lines(|i| " ".repeat(i % 4096) + "a: |\n", size)
                }),
            ),
            (
                "key block",
                Box::new(|size| fill("password:\n", "  - a: b\n\n", "", size)),
            ),
            (
                "indent secrets",
                Box::new(|size| lines(|i| " ".repeat(i % 4096) + "password:\n", size)),
            ),
            (
                "mixed indents",
                Box::new(|size| fill("", "  password:\n\tx\n", "", size)),
            ),
            (
                "nested pairs",
                Box::new(|size| {
                    fill("", "«“", "", size / 2)
                        + "password is x"
                        + &"”»".repeat(size / 8)
                        + "\n\nBye"
                }),
            ),
            (
                "balanced nesting",
                Box::new(|size| {
                    fill("", "«“", "password is red horse", size / 2)
                        + &"”»".repeat(size / 10)
                        + "\n\nBye"
                }),
            ),
            (
                "balanced cjk",
                Box::new(|size| {
                    fill("", "「『", "密码是 red horse", size / 2)
                        + &"』」".repeat(size / 12)
                        + "\n\nBye"
                }),
            ),
            (
                "balanced lines",
                Box::new(|size| {
                    fill("", "«“\n", "password is red horse", size / 2)
                        + &"”»\n".repeat(size / 12)
                        + "\nBye"
                }),
            ),
            (
                "deep flow",
                Box::new(|size| fill("password: ", "{[", "x", size / 2) + &"]}".repeat(size / 4)),
            ),
        ];
        let best = |text: &str| (0..3).map(|_| timed(text)).min().unwrap_or_default();
        for (name, family) in &families {
            let (small, big) = (best(&family(100_000)), best(&family(200_000)));
            assert!(
                big.as_secs_f64() <= 2.6 * small.as_secs_f64().max(1e-3),
                "P5 {name}: {small:?} -> {big:?}"
            );
        }
    }

    /// The masked chars of `link_scan`, by char index.
    fn by_char(text: &str) -> Vec<bool> {
        let mut bytes = vec![false; text.len()];
        link_scan(text)
            .iter()
            .for_each(|&(start, end)| bytes[start..end].fill(true));
        text.char_indices().map(|(at, _)| bytes[at]).collect()
    }

    /// P6: U+E000 and U+FFFD are `x` for every class test and every length cap.
    fn p6(text: &str) -> Result<(), TestCaseError> {
        let x: String = text
            .chars()
            .map(|ch| if super::is_sentinel(ch) { 'x' } else { ch })
            .collect();
        prop_assert_eq!(by_char(text), by_char(&x), "{:?}", text);
        Ok(())
    }

    #[test]
    fn p7_every_case_keeps_main_masking() {
        for &(_, text, _, _) in CASES.iter().chain(PR1B_CASES).chain(PR2_CASES) {
            p1_and_p7(text).unwrap();
        }
        built_cases()
            .iter()
            .for_each(|case| p1_and_p7(&case.1).unwrap());
        refusal_cases()
            .iter()
            .for_each(|case| p1_and_p7(&case.1).unwrap());
        owned_cells()
            .iter()
            .for_each(|(text, _)| p4(text, &[]).unwrap());
    }

    /// P4: the PR2 spans hold the PR1 spans, and mask each key-column cell.
    fn p4(text: &str, hide: &[std::ops::Range<usize>]) -> Result<(), TestCaseError> {
        let cover = |tables: bool| {
            let mut bytes = vec![false; text.len()];
            super::scan(text, tables)
                .iter()
                .for_each(|&(start, end)| bytes[start..end].fill(true));
            bytes
        };
        let (pr1, pr2) = (cover(false), cover(true));
        prop_assert!(
            pr1.iter().zip(&pr2).all(|(pr1, pr2)| !pr1 || *pr2),
            "lost a PR1 byte: {text:?}"
        );
        for range in hide {
            prop_assert!(
                pr2[range.clone()].iter().all(|&masked| masked),
                "{text:?} {range:?}"
            );
        }
        p1_and_p7(text)
    }

    /// P2-1: a pipe-free delimiter adds no span where no table rule applies.
    #[test]
    fn a_text_with_no_table_keeps_its_spans() {
        for text in PR2_SAME {
            assert_eq!(
                super::scan(text, true),
                super::scan(text, false),
                "{text:?}"
            );
        }
    }

    const ALPHABET: &[&str] = &[
        "|",
        "-",
        ":",
        "=",
        "\"",
        "'",
        "“",
        "”",
        "„",
        "«",
        "»",
        "‹",
        "›",
        "‘",
        "’",
        "「",
        "」",
        "\\",
        "`",
        "~",
        "#",
        "[",
        "]",
        "{",
        "}",
        ".",
        "!",
        "?",
        "…",
        "。",
        "\n",
        "\r",
        "\t",
        " ",
        "\u{A0}",
        "\u{200B}",
        "\u{2028}",
        "\u{E000}",
        "\u{FFFD}",
        "é",
        "\u{300}",
        "*",
        "_",
        "password",
        "pin",
        "token",
        "mot de passe",
        "mdp",
        "密码",
        "is",
        "est",
        "是",
        "for",
        "a",
        "abcd",
        "x",
    ];

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn p1_spans_are_well_formed(tokens in prop::collection::vec(prop::sample::select(ALPHABET), 0..600)) {
            let text: String = tokens.concat();
            let text = &text[..text.floor_char_boundary(4096)];
            p1_and_p7(text)?;
        }

        #[test]
        fn p7_a_planted_text_keeps_main_masking((text, _, _) in planted()) {
            p1_and_p7(&text)?;
        }

        #[test]
        fn p1_and_p7_hold_on_owned_texts((text, _, _) in owned()) {
            p1_and_p7(&text)?;
        }

        #[test]
        fn p4_tables_only_add_spans((text, hide) in tables()) {
            p4(&text, &hide)?;
        }

        /// P4 on texts of pipes, dashes, keys and quotes, with no table promised.
        #[test]
        fn p4_pipe_texts_only_add_spans(tokens in prop::collection::vec(prop::sample::select(ALPHABET), 0..600)) {
            let text: String = tokens.concat();
            p4(&text[..text.floor_char_boundary(4096)], &[])?;
        }

        #[test]
        fn p6_a_sentinel_reads_as_x(tokens in prop::collection::vec(prop::sample::select(ALPHABET), 0..600)) {
            let text: String = tokens.concat();
            p6(&text[..text.floor_char_boundary(4096)])?;
        }

        /// P6 at the caps: Entry keys of 63–66 and link windows of 95–98 effective bytes.
        #[test]
        fn p6_holds_at_the_caps(forms in prop::collection::vec(prop::sample::select(&["\u{E000}", "\u{FFFD}", "x"][..]), 87..=90), shape in 0..3usize) {
            let run = forms[24..].concat();
            let text = match shape {
                0 => format!("password: red horse\n\"{run}\": ok"),
                1 => format!("password: red horse\n{run}: ok"),
                _ => format!("password for {} is hunter2 horse", forms.concat()),
            };
            p6(&text)?;
        }
    }
}
