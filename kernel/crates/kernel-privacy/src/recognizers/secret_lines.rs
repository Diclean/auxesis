//! SECRET-1: four secret forms the older scans miss. A session or auth cookie
//! value (`sessionid=…`, or any pair after `Cookie:` / `Set-Cookie:`), a value on
//! the line after its label (`Passphrase` then the words), a value in a CSV/TSV
//! column whose header names a secret, and a lower-case AWS access key id glued
//! to a word. Like the scans next to it, its spans are only added to the older
//! spans; it never removes one. Each line is read a bounded number of times, so
//! the scan is linear.

use std::sync::LazyLock;

use regex::Regex;

/// The shortest cookie value.
const MIN_COOKIE: usize = 8;
/// Bytes of a `Cookie:` line read for its pairs.
const MAX_COOKIE_LINE: usize = 4096;
/// Rows of one table read under its header by the capped passes.
const MAX_ROWS: usize = 10_000;
/// Words of a passphrase on the line after its label.
const MAX_PHRASE_WORDS: usize = 8;
/// Words of any value on the line after its label, however long.
const MAX_LINE_WORDS: usize = 16;

/// A session or auth cookie name, then `=` and its value (closed list).
static COOKIE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:^|[^A-Za-z0-9_.\-])(?:sessionid|session_id|session|sid|user_session|",
        r"auth|auth_token|token|csrftoken|csrf_token|remember_token|remember_me|",
        r"phpsessid|jsessionid|aspsessionid|asp\.net_sessionid|connect\.sid|",
        r"laravel_session|ci_session|_session_id)=([^\s;,]+)"
    ))
    .expect("cookie name list compiles")
});

/// A cookie header: its pairs run to the line end.
static COOKIE_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[^A-Za-z0-9-])(?:set-)?cookie[ \t]*:").expect("cookie header compiles")
});

/// Cookie attributes: a `Set-Cookie` pair that is no value.
const ATTRIBUTES: &[&str] = &[
    "path",
    "domain",
    "expires",
    "max-age",
    "samesite",
    "httponly",
    "secure",
    "priority",
    "partitioned",
];

/// A label alone on its line (a bullet or a number before it allowed), then
/// the line that holds its value.
static LABEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?im)^[ \t]*(?:(?:[-*•‣◦·]|[0-9]{1,3}[.)])[ \t]+)?(passphrase|password|pin|api[ _-]?key|secret|mot de passe|",
        r"phrase secr[èe]\x{300}?te)[ \t]*:?[ \t]*\r?\n([^\r\n]*)"
    ))
    .expect("label lines compile")
});

/// A passphrase key, then its words on the same line: in brackets or quotes, or
/// to the line end (a colon optional) when they read as no sentence.
static PHRASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:passphrase|pass phrase|phrase secr[èe]\x{300}?te)\b[ \t]*(?:",
        r#"[(“"«]([^()“”"«»\r\n]+)[)”"»]|:?[ \t]*([^\r\n]+))"#
    ))
    .expect("phrase shapes compile")
});

/// An AWS access key id in any case, its sixteen characters read by the caller.
static AWS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:akia|asia)[0-9a-z]{16}").expect("AWS shape compiles"));

/// The secret spans of the four forms in `text`.
pub(crate) fn lines_scan(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    cookies(text, &mut spans);
    labels(text, &mut spans);
    let headers = columns(text, &mut spans);
    phrases(text, &headers, &mut spans);
    glued_aws(text, &mut spans);
    spans.sort_unstable();
    spans.dedup();
    spans
}

/// `text[start..end]` with quotes trimmed in pairs and outer blanks dropped.
fn trimmed(text: &str, start: usize, end: usize) -> (usize, usize) {
    let cell = &text[start..end];
    let mut start = start + cell.len() - cell.trim_start().len();
    let mut end = start + text[start..end].trim_end().len();
    let cell = &text[start..end];
    if cell.len() >= 2 && (cell.starts_with('"') && cell.ends_with('"')) {
        start += 1;
        end -= 1;
    }
    (start, end)
}

/// A cookie value: [`MIN_COOKIE`] bytes or more, hidden whole however long.
fn cookie_value(value: &str) -> bool {
    value.len() >= MIN_COOKIE
}

fn cookies(text: &str, spans: &mut Vec<(usize, usize)>) {
    for found in COOKIE_RE.captures_iter(text) {
        if let Some(value) = found.get(1) {
            let (start, end) = trimmed(text, value.start(), value.end());
            if cookie_value(&text[start..end]) {
                spans.push((start, end));
            }
        }
    }
    let mut reach = 0;
    for cue in COOKIE_HEADER_RE.find_iter(text) {
        if cue.end() <= reach {
            continue;
        }
        // Cap before searching: a long line is read once, not once per cue.
        let mut cap = text.len().min(cue.end() + MAX_COOKIE_LINE);
        while !text.is_char_boundary(cap) {
            cap -= 1;
        }
        let end = text[cue.end()..cap]
            .find(['\n', '\r'])
            .map_or(cap, |at| cue.end() + at);
        reach = end;
        let mut at = cue.end();
        for pair in text[cue.end()..end].split(';') {
            let pair_start = at;
            at += pair.len() + 1;
            let Some((name, _)) = pair.split_once('=') else {
                continue;
            };
            if ATTRIBUTES.contains(&name.trim().to_ascii_lowercase().as_str()) {
                continue;
            }
            let value_start = pair_start + name.len() + 1;
            let (start, stop) = trimmed(text, value_start, pair_start + pair.len());
            if cookie_value(&text[start..stop]) && !text[start..stop].contains(char::is_whitespace)
            {
                spans.push((start, stop));
            }
        }
    }
}

/// The next line after an explicit secret label is its value, sentence, colon
/// or not, up to [`MAX_LINE_WORDS`] words of any length.
fn labels(text: &str, spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(found) = LABEL_RE.captures_at(text, from) {
        let Some(line) = found.get(2) else {
            break;
        };
        // The value line may be a label itself: read it again as one.
        from = line.start();
        let (start, end) = trimmed(text, line.start(), line.end());
        let value = &text[start..end];
        if !value.is_empty() && value.split_whitespace().count() <= MAX_LINE_WORDS {
            spans.push((start, end));
        }
    }
}

/// `headers` are the table header lines, whose cells are names, not phrases.
fn phrases(text: &str, headers: &[(usize, usize)], spans: &mut Vec<(usize, usize)>) {
    for found in PHRASE_RE.captures_iter(text) {
        let key = found.get(0).map_or(0, |m| m.start());
        let at = headers.partition_point(|&(_, end)| end < key);
        if headers.get(at).is_some_and(|&(start, _)| start <= key) {
            continue;
        }
        let (inner, words) = match (found.get(1), found.get(2)) {
            (Some(inner), _) => (inner, true),
            (None, Some(rest)) => {
                let last = rest.as_str().trim_end();
                let prose = if text[key..rest.start()].contains(':') {
                    last.ends_with('.')
                } else {
                    last.ends_with(['.', '!', '?'])
                };
                (rest, !prose)
            }
            _ => continue,
        };
        let (start, end) = trimmed(text, inner.start(), inner.end());
        let count = text[start..end].split_whitespace().count();
        if words && (1..=MAX_PHRASE_WORDS).contains(&count) {
            spans.push((start, end));
        }
    }
}

/// The header names a table pass reads: main's list under the row cap, the
/// wider list with no cap (SECRET-FR-HDR-1), and that list with a bare `pass`
/// and the password manager export names (SECRET-LEAK-294B). Each pass only
/// adds spans, so a new name never changes what the older passes hide.
#[derive(Clone, Copy, PartialEq)]
enum Names {
    Main,
    Wide,
    Export,
}

impl Names {
    fn wide(self) -> bool {
        self != Names::Main
    }
}

/// `cell` lower-cased, without blanks, `_` or `-`; `wide` also drops a last
/// colon (`Mot de passe :`), no-break blanks and combining accents, so an NFD
/// `Clé privée` reads as its NFC form (SECRET-FR-HDR-P3).
fn folded(cell: &str, wide: bool) -> String {
    let cell = cell.trim().trim_matches('"');
    let cell = if wide {
        cell.trim_end_matches([':', ' ', '\t', '\u{a0}', '\u{202f}'])
    } else {
        cell
    };
    if cell.is_ascii() {
        // ASCII lowercases to one byte and has none of the wide-only
        // characters above, so the Unicode path is pure overhead here.
        let mut out = String::with_capacity(cell.len());
        for &byte in cell.as_bytes() {
            if matches!(byte, b'_' | b'-' | b' ') {
                continue;
            }
            out.push(byte.to_ascii_lowercase() as char);
        }
        return out;
    }
    cell.chars()
        .filter(|ch| !matches!(ch, '_' | '-' | ' '))
        .filter(|&ch| !wide || !matches!(ch, '\u{a0}' | '\u{202f}' | '\u{300}'..='\u{36f}'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// A header cell that names a secret column (closed list); a wide list adds
/// the French names and the compound English ones (SECRET-FR-HDR-1), the
/// export list a bare `pass` and the password manager column names.
fn secret_header(cell: &str, names: Names) -> bool {
    let wide = names.wide();
    let folded = folded(cell, wide);
    [
        "password",
        "passwd",
        "pwd",
        "apikey",
        "token",
        "secret",
        "privatekey",
        "passphrase",
        "pin",
    ]
    .contains(&folded.as_str())
        || wide
            && [
                "motdepasse",
                "mdp",
                "codesecret",
                "codepin",
                "cleprivee",
                "cléprivée",
                "passcode",
                "secretkey",
                "clientsecret",
                "apisecret",
                "accesstoken",
                "authtoken",
                "apitoken",
            ]
            .contains(&folded.as_str())
        || names == Names::Export
            && ["pass", "loginpassword", "logintotp", "totp", "otpauth"].contains(&folded.as_str())
}

/// The cell ranges of `text[start..end]` split on `delim`, a `"…"` cell read as
/// one even when it holds the delimiter.
fn cells(text: &str, start: usize, end: usize, delim: u8) -> Vec<(usize, usize)> {
    let (mut out, mut from, mut quoted) = (Vec::new(), start, false);
    for (at, &byte) in text.as_bytes()[start..end].iter().enumerate() {
        let at = start + at;
        match byte {
            b'"' => quoted = !quoted,
            byte if byte == delim && !quoted => {
                out.push((from, at));
                from = at + 1;
            }
            _ => {}
        }
    }
    out.push((from, end));
    out
}

/// An open table: its delimiter, cell count, secret columns and rows read.
struct Table {
    delim: u8,
    count: usize,
    secret: Vec<usize>,
    rows: usize,
    /// The last row broke it: a header line next opens its own table.
    broke: bool,
    /// A cookie leads its header: the residue view reads the header after
    /// the masked value, and each row from its first hidden cell on.
    tail: bool,
    /// A blank line came after the last row (`wide` passes only).
    gap: bool,
    /// The header line's range.
    head: (usize, usize),
    /// The header ends with a blank cell (`id,password,city,`).
    loose: bool,
    /// Secret columns only the export list names, sorted.
    extra: Vec<usize>,
    /// Secret columns named a bare `pass`, sorted: a verdict there is no value.
    verdict: Vec<usize>,
}

/// A pass/fail cell (`yes`, `fail`, `✓`): under a bare `pass` header it is a
/// result, not a password.
fn verdict(cell: &str) -> bool {
    [
        "yes", "no", "y", "n", "true", "false", "pass", "passed", "fail", "failed", "ok", "oui",
        "non", "x", "0", "1", "error", "skip", "skipped", "pending", "na", "n/a", "none", "✓", "✗",
        "✔", "✘",
    ]
    .contains(&cell.trim().trim_matches('"').trim().to_lowercase().as_str())
}

/// The table a header line opens, if a cell of it names a secret column.
fn header(text: &str, start: usize, end: usize, names: Names) -> Option<Table> {
    b",\t;|".iter().find_map(|&delim| {
        let row = cells(text, start, end, delim);
        let short = row.iter().all(|&(s, e)| e - s <= 64);
        let cell = |column: usize| &text[row[column].0..row[column].1];
        let led = |column: usize| {
            let (pair, name) = cell(column).trim().rsplit_once(' ').unwrap_or_default();
            pair.contains('=') && secret_header(name, names)
        };
        let secret: Vec<usize> = (0..row.len())
            .filter(|&column| secret_header(cell(column), names) || led(column))
            .collect();
        let tail = secret
            .iter()
            .any(|&column| !secret_header(cell(column), names));
        let extra: Vec<usize> = secret
            .iter()
            .copied()
            .filter(|&column| {
                names == Names::Export && !secret_header(cell(column), Names::Wide) && !led(column)
            })
            .collect();
        let verdict = extra
            .iter()
            .copied()
            .filter(|&column| folded(cell(column), true) == "pass")
            .collect();
        (row.len() >= 2 && short && !secret.is_empty()).then_some(Table {
            delim,
            count: row.len(),
            secret,
            rows: 0,
            broke: false,
            tail,
            gap: false,
            head: (start, end),
            loose: row
                .last()
                .is_some_and(|&(s, e)| text[s..e].trim().is_empty()),
            extra,
            verdict,
        })
    })
}

/// Hides the secret cells of every table and returns its header lines. Rows
/// are read twice: a line at a time, and as CSV records whose quoted cells may
/// hold line breaks, so a record never hides less than its lines. Each is read
/// again `wide`: no row cap (SECRET-LEAK-294B: filler rows pushed a password
/// past [`MAX_ROWS`]), the wider header list, and a table kept across blank
/// lines (SECRET-FR-HDR-1); its spans only add, its header lines are not kept.
fn columns(text: &str, spans: &mut Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut headers = Vec::new();
    // A header needs two cells: with no delimiter there is no table to read.
    if !text.bytes().any(|b| b",\t;|".contains(&b)) {
        return headers;
    }
    tables(text, false, Names::Main, spans, &mut headers);
    tables(text, true, Names::Main, spans, &mut headers);
    tables(text, false, Names::Wide, spans, &mut Vec::new());
    tables(text, true, Names::Wide, spans, &mut Vec::new());
    headers.sort_unstable();
    headers.dedup();
    headers
}

/// The secret cells of every table the export list names (a bare `pass`, the
/// password manager columns), read like the wide pair of [`columns`]. Not a
/// part of [`lines_scan`]: the gate adds these spans on top of what main's
/// scans and residue rounds already hide, so they can only hide more
/// (SECRET-LEAK-294B).
pub(crate) fn export_scan(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    if text.bytes().any(|b| b",\t;|".contains(&b)) {
        tables(text, false, Names::Export, &mut spans, &mut Vec::new());
        tables(text, true, Names::Export, &mut spans, &mut Vec::new());
    }
    spans.sort_unstable();
    spans.dedup();
    spans
}

/// The end of the record at `at`: its line end, or with `records` the end of
/// the line that closes a quote the record opens, however far; its line end
/// when no line closes it. Linear over a table: a scan from a line
/// with an odd quote count stops at the next such line, and when none closes
/// it every later line is even and never scans.
fn record_end(text: &str, at: usize, records: bool) -> usize {
    let bytes = text.as_bytes();
    let first = memchr_nl(bytes, at);
    let mut open = records && odd(bytes, at, first);
    let mut end = first;
    while open && end < bytes.len() {
        let next = memchr_nl(bytes, end + 1);
        open ^= odd(bytes, end + 1, next);
        end = next;
    }
    if open {
        first
    } else {
        end
    }
}

/// The next line break at or after `from`, or the text end.
fn memchr_nl(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |n| from + n)
}

/// Whether `bytes[from..to]` holds an odd number of quotes.
fn odd(bytes: &[u8], from: usize, to: usize) -> bool {
    bytes[from..to].iter().filter(|&&b| b == b'"').count() % 2 == 1
}

fn tables(
    text: &str,
    records: bool,
    list: Names,
    spans: &mut Vec<(usize, usize)>,
    headers: &mut Vec<(usize, usize)>,
) {
    let wide = list.wide();
    let max_rows = if wide { usize::MAX } else { MAX_ROWS };
    let no_cr = |next: usize| next - usize::from(text[..next].ends_with('\r'));
    let mut table: Option<Table> = None;
    let (mut at, mut quoted_break) = (0, false);
    while at < text.len() {
        let after_break = std::mem::take(&mut quoted_break);
        let mut next = record_end(text, at, records && table.is_some());
        let end = no_cr(next);
        if let Some(open) = table.as_mut().filter(|_| wide) {
            // A blank line after a row keeps the table; the next line goes on
            // with it only when it has the table's shape and is neither a
            // header nor prose. Right under the header it closes the table, as
            // the residue view ends a masked header cell's line there.
            if text[at..end].trim().is_empty() && open.rows > 0 {
                (open.gap, quoted_break) = (true, after_break);
                at = next + 1;
                continue;
            }
            if std::mem::take(&mut open.gap) {
                // A header with a value cell (`7,token,Paris`) is a row.
                let row = row_cells(text, at, end, open);
                if row.len() != open.count
                    || header(text, at, end, list).is_some() && names(text, &row)
                    || heading(text, at, end, open)
                    || prose(text, at, end, open)
                {
                    table = None;
                }
            }
        }
        let width = table.as_ref().map(|open| open.count);
        if table.as_ref().is_some_and(|open| open.broke) && header(text, at, end, list).is_some() {
            table = None;
        }
        if let Some(open) = table.as_mut() {
            open.broke = false;
            let row = row_cells(text, at, end, open);
            let broken = row.len() != open.count && !text[at..end].trim().is_empty();
            if broken && text[at..end].contains('"') && open.rows < max_rows {
                // A quoted row that breaks the table hides where the secret
                // column is, its quote closed or not: it goes whole, and the
                // rows after it still belong to the table unless it heads one.
                (open.rows, open.broke, quoted_break) = (open.rows + 1, true, true);
                whole(text, at, end, spans);
                if header(text, at, no_cr(record_end(text, at, false)), list).is_some() {
                    table = None;
                }
            } else if broken || text[at..end].trim().is_empty() || open.rows >= max_rows {
                table = None;
            } else {
                open.rows += 1;
                // A row that names a secret in another column opens a new
                // table of the same width; its columns add to the old ones.
                // Its cell under an old secret column is still hidden, even a
                // secret name: `alice,secret,token` is a password `secret`.
                let new = header(text, at, end, list)
                    .filter(|new| new.delim == open.delim && new.secret != open.secret);
                if new.is_some() && !names(text, &row) {
                    // A secret name beside a value is no header: the row goes.
                    whole(text, at, end, spans);
                }
                // Only a row made of rule cells (`|---|:--|`) is a divider.
                let divider = row.iter().all(|&(s, e)| {
                    let (s, e) = trimmed(text, s, e);
                    text[s..e].bytes().all(|b| b"-:= ".contains(&b))
                });
                let mut hidden: Vec<(usize, usize)> = Vec::new();
                let mut tail = 0;
                for &column in &open.secret {
                    let raw = &text[row[column].0..row[column].1];
                    let (mut start, mut stop) = trimmed(text, row[column].0, row[column].1);
                    if !records {
                        // A line keeps a cell's quotes, so none stays clear.
                        start = row[column].0 + raw.len() - raw.trim_start().len();
                        stop = start.max(row[column].0 + raw.trim_end().len());
                    } else {
                        // A record's value drops the blanks inside its quotes
                        // too, as the residue view ends each stand-in with a
                        // line break; a value that still holds one keeps its
                        // quotes.
                        let (inner, last) = trimmed(text, start, stop);
                        if text[inner..last].contains('\n') {
                            start = row[column].0 + raw.len() - raw.trim_start().len();
                            stop = row[column].0 + raw.trim_end().len();
                        } else {
                            (start, stop) = (inner, last);
                        }
                    }
                    let cell = &text[start..stop];
                    if cell.is_empty() || divider || start < tail {
                        continue;
                    }
                    if open.verdict.binary_search(&column).is_ok() && verdict(cell) {
                        continue;
                    }
                    if secret_header(cell, list) || open.tail {
                        // A secret name as a value (`alice,secret,token`): its
                        // whole line goes, the password beside it too; one
                        // line per row keeps it linear.
                        let line = memchr_nl(text.as_bytes(), start).min(end);
                        tail = start + text[start..line].trim_end().len();
                        stop = tail.max(stop);
                        start = text[at..start].rfind('\n').map_or(at, |n| at + n + 1);
                    }
                    // Cells apart only by delimiters, blanks, quotes or secret
                    // names are one span: nothing between two values is clear.
                    let gap = |from: usize| {
                        text[from..start]
                            .split(char::from(open.delim))
                            .all(|piece| {
                                let piece = piece.trim().trim_matches('"');
                                piece.is_empty() || secret_header(piece, list)
                            })
                    };
                    match hidden.last_mut() {
                        Some(prev) if prev.1 <= start && gap(prev.1) => prev.1 = stop,
                        _ => hidden.push((start, stop)),
                    }
                }
                // A record over several lines is hidden from its first secret
                // cell to its last, so no stand-in splits it.
                match (hidden.first(), hidden.last()) {
                    (Some(&(start, _)), Some(&(_, stop))) if text[at..end].contains('\n') => {
                        spans.push((start, stop));
                    }
                    _ => spans.extend(hidden),
                }
                if let Some(mut new) = new {
                    // A column either header names from the older lists is
                    // no export column, and has no verdicts.
                    let older = |table: &Table, column: usize| {
                        table.secret.binary_search(&column).is_ok()
                            && table.extra.binary_search(&column).is_err()
                    };
                    let joined = |a: &[usize], b: &[usize]| {
                        let mut out: Vec<usize> = a
                            .iter()
                            .chain(b)
                            .copied()
                            .filter(|&column| !older(&new, column) && !older(open, column))
                            .collect();
                        out.sort_unstable();
                        out.dedup();
                        out
                    };
                    let extra = joined(&new.extra, &open.extra);
                    let verdict = joined(&new.verdict, &open.verdict);
                    (new.extra, new.verdict) = (extra, verdict);
                    new.secret.extend(open.secret.iter().copied());
                    new.secret.sort_unstable();
                    new.secret.dedup();
                    headers.push((at, end));
                    *open = new;
                }
            }
        }
        if table.is_none() {
            next = record_end(text, at, false);
            let end = no_cr(next);
            table = header(text, at, end, list);
            if table.is_some() {
                headers.push((at, end));
                if after_break || table.as_ref().map(|open| open.count) == width {
                    // A header of the same width right under a secret table's
                    // rows, or right after a broken quoted row, may be a row
                    // of secret names: it goes whole.
                    whole(text, at, end, spans);
                }
            }
        }
        at = next + 1;
    }
}

/// A line that reads as a header of any table: every cell a name, or a cell
/// that is a cell of `open`'s header (`id,name,city` under `id,password,city`).
fn heading(text: &str, at: usize, end: usize, open: &Table) -> bool {
    let cell = |(s, e): (usize, usize)| text[s..e].trim().trim_matches('"').to_lowercase();
    let row: Vec<String> = cells(text, at, end, open.delim)
        .into_iter()
        .map(cell)
        .collect();
    let named = row.iter().all(|cell| {
        cell.chars().any(char::is_alphabetic)
            && cell
                .chars()
                .all(|ch| ch.is_alphabetic() || " _-".contains(ch))
    });
    // A set, so a wide row is matched in one pass (a header of n cells and a
    // row of n cells cost n lookups, not n²).
    let head: std::collections::HashSet<String> = cells(text, open.head.0, open.head.1, open.delim)
        .into_iter()
        .map(cell)
        .collect();
    named
        || row
            .iter()
            .any(|cell| !cell.is_empty() && head.contains(cell))
}

/// The cells of a row of `open`, a blank last cell past its width dropped
/// (`7,pw,Paris,`), so a trailing delimiter does not break the table; under a
/// header that ends with a blank cell, an unquoted row one cell short gets it
/// empty.
fn row_cells(text: &str, at: usize, end: usize, open: &Table) -> Vec<(usize, usize)> {
    let mut row = cells(text, at, end, open.delim);
    // A quoted row keeps main's reading: one cell short, it goes whole.
    if open.loose && row.len() + 1 == open.count && !text[at..end].contains('"') {
        row.push((end, end));
    }
    if row.len() == open.count + 1
        && row
            .last()
            .is_some_and(|&(s, e)| text[s..e].trim().is_empty())
    {
        row.pop();
    }
    row
}

/// A line that reads as a sentence: four words or more, with a blank after
/// each delimiter (`Thanks, see you, Bob`), or ending `.`, `!` or `?` with four
/// words outside `open`'s secret cells (`2,violet tractor humming seventy.` is
/// a passphrase row).
fn prose(text: &str, at: usize, end: usize, open: &Table) -> bool {
    let line = text[at..end].trim().trim_end_matches('"');
    if line.split_whitespace().count() < 4 {
        return false;
    }
    let spaced = line
        .as_bytes()
        .windows(2)
        .all(|pair| pair[0] != open.delim || pair[1] == b' ');
    if spaced {
        return true;
    }
    if !line.ends_with(['.', '!', '?']) {
        return false;
    }
    // `secret` is sorted, so a wide row costs cells × log(columns), not cells².
    let outside: usize = cells(text, at, end, open.delim)
        .iter()
        .enumerate()
        .filter(|(column, _)| open.secret.binary_search(column).is_err())
        .map(|(_, &(s, e))| text[s..e].split_whitespace().count())
        .sum();
    outside >= 4
}

/// Whether every cell of `row` reads as a column name or is blank.
fn names(text: &str, row: &[(usize, usize)]) -> bool {
    row.iter().all(|&(s, e)| {
        let cell = text[s..e].trim().trim_matches('"');
        cell.chars()
            .all(|ch| ch.is_alphabetic() || " _-".contains(ch))
    })
}

/// Hides `text[at..end]` whole, outer blanks dropped.
fn whole(text: &str, at: usize, end: usize, spans: &mut Vec<(usize, usize)>) {
    let line = &text[at..end];
    let start = at + line.len() - line.trim_start().len();
    if start < at + line.trim_end().len() {
        spans.push((start, at + line.trim_end().len()));
    }
}

/// Vowels at most in an all-letter id body: random letters, not a word.
const MAX_ID_VOWELS: usize = 5;

/// Letter pairs seen ten times or fewer across an English word list
/// (`/usr/share/dict/words`, 143 pairs): random letters hold one far more often
/// than words do.
const RARE_PAIRS: &str = concat!(
    "bqbxbzcbcfcgcjcvcwcxdqdxfcfjfkfqfvfxfzgjgqgvgxgzhjhqhxhzjbjcjdjfjgjhjjjk",
    "jljmjnjpjqjrjsjtjvjwjxjyjzkqkvkxkzljlqlxmjmqmxmzpqpvpxpzqaqbqcqdqeqfqgqh",
    "qiqjqkqlqmqnqoqpqqqrqsqtqvqwqxqyqzrxsxtqtxvbvcvdvfvgvhvjvkvlvmvnvpvqvsvt",
    "vwvxvzwjwqwvwxxdxgxjxkxnxqxrxvxxxzyjyqyyzczfzgzhzjzkzmznzpzqzrzszvzwzx",
);

/// An id body with a digit, or a body of sixteen letters that reads as no word
/// (few vowels, or a pair words almost never hold) after `akia` in any case or
/// a lower-case `asia`.
fn id_body(key: &str) -> bool {
    let body = &key.as_bytes()[4..];
    if body.iter().any(u8::is_ascii_digit) {
        return true;
    }
    let lower = !key.bytes().any(|b| b.is_ascii_uppercase());
    let folded = body.to_ascii_lowercase();
    let vowels = folded.iter().filter(|b| b"aeiou".contains(b)).count();
    let rare = folded
        .windows(2)
        .any(|pair| RARE_PAIRS.as_bytes().chunks(2).any(|known| known == pair));
    (lower || key[..4].eq_ignore_ascii_case("akia")) && (vowels <= MAX_ID_VOWELS || rare)
}

fn glued_aws(text: &str, spans: &mut Vec<(usize, usize)>) {
    let bytes = text.as_bytes();
    for key in AWS_RE.find_iter(text) {
        let joined = key.start() > 0 && bytes[key.start() - 1].is_ascii_alphanumeric();
        if !joined && id_body(key.as_str()) {
            // A glued suffix goes with the id: the word is one value.
            let glued = bytes[key.end()..]
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric());
            spans.push((key.start(), key.end() + glued.count()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{folded, lines_scan};
    use proptest::strategy::Strategy as _;

    fn hidden(text: &str) -> Vec<&str> {
        lines_scan(text).iter().map(|&(s, e)| &text[s..e]).collect()
    }

    #[test]
    fn each_form_hides_only_its_value() {
        assert_eq!(hidden("csrftoken=Zx81mNq02LpWv7Ks"), ["Zx81mNq02LpWv7Ks"]);
        assert_eq!(
            hidden("Set-Cookie: a=k2Lp9xQe7Rv3Wm8T; Path=/; Expires=Wed, 21 Oct 2026"),
            ["k2Lp9xQe7Rv3Wm8T"]
        );
        assert_eq!(hidden("PIN\r\n4821"), ["4821"]);
        assert_eq!(hidden("id,\"pwd\"\n1,\"a,b,c9\""), ["\"a,b,c9\"", "a,b,c9"]);
        assert_eq!(hidden("akiaiosfodnn7exampleok"), ["akiaiosfodnn7exampleok"]);
        assert_eq!(
            hidden("Re: your Passphrase (violet tractor humming seventy)"),
            ["violet tractor humming seventy"]
        );
        assert_eq!(
            hidden("Passphrase: cerise lune papier"),
            ["cerise lune papier"]
        );
        assert_eq!(
            hidden("Password\nChange it every month."),
            ["Change it every month."]
        );
        assert_eq!(hidden("Passphrase: words!"), ["words!"]);
        assert_eq!(hidden("asiabcdfghjklmnpqrstok"), ["asiabcdfghjklmnpqrstok"]);
    }

    #[test]
    fn lookalikes_stay_clear() {
        for text in [
            "session=short",
            "Password\nChange it every month and never share it with anyone at all, not even the people at the desk.",
            "Passphrase: pick four random words and keep them safe.",
            "Passphrase protection is on for every account.",
            "| token | count |\n|---|---|\n| | 3 |",
            "asianfusionrestaurants",
            "xakiaiosfodnn7example",
            "id,name\n1,2",
            "Mot de passe oublié ?",
        ] {
            assert_eq!(hidden(text), Vec::<&str>::new(), "{text:?}");
        }
    }

    /// 10× the input costs at most 20× the time on every scan path (best of
    /// three): a cookie header, cookie pairs, label lines, a same-line
    /// passphrase, CSV rows, open quotes in CSV rows and AWS ids.
    #[test]
    fn every_path_scales_linearly() {
        use std::time::{Duration, Instant};
        let paths: [(&str, &str, &str); 7] = [
            ("cookie header", "", "Cookie: "),
            ("cookie pairs", "", "Cookie: sid=k2Lp9xQe7Rv3Wm8T;"),
            ("labels", "", "Password\n"),
            ("phrase", "", "Passphrase: "),
            ("csv", "id,password,note\n", "1,Cherry6!,ok\n"),
            ("csv quotes", "id,password,note\n", "1,pw,\"open\n"),
            ("aws", "", "akiabcdfghjklmnpqrst "),
        ];
        let tail = |bytes: usize| {
            let n = bytes / 16;
            format!(
                "id,{}note\n1,{}token",
                "password,".repeat(n),
                "secret,".repeat(n)
            )
        };
        let (s, l) = (tail(160_000), tail(1_600_000));
        let start = Instant::now();
        let _ = lines_scan(&s);
        let small = start.elapsed();
        let start = Instant::now();
        let _ = lines_scan(&l);
        let large = start.elapsed();
        assert!(
            large <= small * 20 + Duration::from_millis(50),
            "csv tail: 160 KB {small:?}, 1.6 MB {large:?}"
        );
        for (name, head, unit) in paths {
            let text = |bytes: usize| head.to_string() + &unit.repeat(bytes / unit.len());
            let best = |t: &str| {
                (0..3)
                    .map(|_| {
                        let start = Instant::now();
                        let _ = lines_scan(t);
                        start.elapsed()
                    })
                    .min()
                    .expect("three runs")
            };
            let (s, l) = (best(&text(160_000)), best(&text(1_600_000)));
            assert!(
                l <= s * 20 + Duration::from_millis(50),
                "{name}: 160 KB {s:?}, 1.6 MB {l:?}"
            );
        }
    }

    /// The full trim/filter/lowercase body, kept as the oracle for the ASCII
    /// fast path.
    fn folded_reference(cell: &str, wide: bool) -> String {
        let cell = cell.trim().trim_matches('"');
        let cell = if wide {
            cell.trim_end_matches([':', ' ', '\t', '\u{a0}', '\u{202f}'])
        } else {
            cell
        };
        cell.chars()
            .filter(|ch| !matches!(ch, '_' | '-' | ' '))
            .filter(|&ch| !wide || !matches!(ch, '\u{a0}' | '\u{202f}' | '\u{300}'..='\u{36f}'))
            .flat_map(char::to_lowercase)
            .collect()
    }

    #[test]
    fn folded_ascii_fast_path_matches_the_unicode_path_on_edges() {
        for (cell, wide) in [
            ("", false),
            (" Password ", false),
            ("PASSWORD\t", false),
            ("\"Mot de passe :\"", true),
            ("CLÉ PRIVÉE", true),
            ("Clé\u{300} privée", true),
            ("\u{202f}pin\u{202f}", true),
            ("Full\u{ff11}\u{ff21}", true),
            ("zero\u{200b}width", false),
            ("中文", true),
        ] {
            assert_eq!(
                folded(cell, wide),
                folded_reference(cell, wide),
                "{cell:?} {wide}"
            );
        }
    }

    /// Every ASCII byte, alone and in short mixed cells, under both header
    /// lists: the fast branch is covered by enumeration, not by a strategy.
    #[test]
    fn folded_ascii_fast_path_matches_every_byte() {
        for byte in 0x00u8..=0x7f {
            let ch = char::from(byte);
            for cell in [
                ch.to_string(),
                format!(" {ch} "),
                format!("\"{ch}\":"),
                format!("A{ch}z 9"),
            ] {
                for wide in [false, true] {
                    assert_eq!(
                        folded(&cell, wide),
                        folded_reference(&cell, wide),
                        "{cell:?} {wide}"
                    );
                }
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        #[test]
        fn folded_fast_path_matches_the_unicode_path(
            cell in folded_text(),
            wide in proptest::prelude::any::<bool>(),
        ) {
            proptest::prop_assert_eq!(
                folded(&cell, wide),
                folded_reference(&cell, wide),
                "{:?} wide={}",
                cell,
                wide
            );
        }
    }

    /// ASCII, mixed and non-ASCII cells: quotes, trimmed delimiters, accents,
    /// invisibles and full-width forms.
    fn folded_text() -> impl proptest::strategy::Strategy<Value = String> {
        proptest::collection::vec(
            proptest::prop_oneof![
                proptest::prelude::any::<char>(),
                proptest::sample::select(vec![
                    ' ', '\t', '"', ':', '_', '-', '\u{a0}', '\u{202f}', '\u{e9}', '\u{301}',
                    '\u{200b}', '\u{200d}', '\u{feff}', '\u{ff11}', '\u{ff21}', '\u{4e2d}',
                ]),
            ],
            0..40,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }
}
