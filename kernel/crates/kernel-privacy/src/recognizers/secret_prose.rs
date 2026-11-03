//! SECRET-PROSE: a password, API key, PIN or cookie whose value follows its key
//! through a prose link (`might be`, `,`, `is`, `will be`, `was`, `changed … to`,
//! `set it to`, `use`, `as`, `such as`, `which is`, `:`), a key written with
//! Markdown escapes (`api\_key`), and a cookie value (`Cookie:`, `Set-Cookie:`, a
//! `name=value; Path=` pair). Like the K-SECRET-TAIL-4 link scan next to it, its
//! spans are only added to the older scans' spans; it never removes one.
//!
//! A value must look like a secret, so prose after a link stays clear: six or more
//! characters with letters and digits, or a password sign (`!`, `@`, `$`, …) with
//! either, or four to eight digits after a PIN key. A bare `token` needs twelve
//! token characters with letters and digits; a bare `key` is left to the older
//! scans (`key` is too common a word). Each key reads at most [`MAX_WORDS`]
//! words of at most [`MAX_WORD`] bytes, on its own line, so the scan is linear
//! with a constant that does not depend on how long the words of the text are.

use std::sync::LazyLock;

use regex::Regex;

/// Words a key reads past to find its value.
const MAX_WORDS: usize = 10;
/// A longer word ends the search: no value is that long.
///
/// [`strong`] caps a value at 256 characters, and a key reads at most
/// [`MAX_WORDS`] words, so a 1,024-byte window let every key of a text dense
/// with long hyphenated words walk ten whole words of it: 255 keys per KiB, and
/// a 1 MiB gate run cost 11.8 s against main's 2.2 s. A word past the cap is
/// not a value — the gate splits a secret span at
/// [`MAX_KEY_SPAN_BYTES`](kernel_privacy::recognizer::MAX_KEY_SPAN_BYTES) and
/// reads prose words, not blobs — so the window is 257 bytes and the scan is
/// linear with a small constant.
const MAX_WORD: usize = 257;
/// Cookie attributes (`; Path=/`) joined to a cookie value.
const MAX_ATTRS: usize = 16;

/// A key in prose, longest alternatives first. `\_` is a Markdown escape.
static KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:\b|_)(set-cookies?|(?:http |browser |session )?cookies?|passwords?|passwd|pwd|",
        r"passphrases?|passcodes?|api(?:\\?[_ -])?keys?|(?:access|secret|private)\\?[_ ]keys?|",
        r"(?:access|auth|bearer)\\?[_ ]tokens?|pins?(?: codes?| numbers?)?|codes? pin|",
        r"mots? de passe|mdp|codes? secrets?|cl[ée]s? api|tokens?|jetons?)\b"
    ))
    .expect("prose key list compiles")
});

/// SECRET-RECALL-1 keys, scanned on their own so they never shadow a
/// [`KEY_RE`] key: recovery and backup codes, a named app's secret
/// (`AWS secret`), and a Wi-Fi key or `clé` up to 40 bytes after `Wi-Fi` on its
/// line (`Wi-Fi: CafeNet / key: …`).
static EXTRA_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:(?:recovery|backup)[ \t]+codes?|",
        r"codes?[ \t]+de[ \t]+(?:r[ée]cup[ée]ration|secours)|",
        r"(?:aws|client|app|webhook|signing|consumer)\\?[_ ]secrets?|",
        r"(?:wi-?fi|wlan|wpa2?)\b[^\n]{0,40}?\b(?:key|cl[ée]|pass)|cl[ée]s?[ \t]+(?:wi-?fi|wpa2?))\b"
    ))
    .expect("extra prose keys compile")
});

/// SECRET-RECALL-2 Wi-Fi keys, scanned on their own like [`EXTRA_KEY_RE`]: a
/// key, `clé`, password or passphrase up to 40 bytes after `Wi-Fi` on its line,
/// or `clé Wi-Fi`, `mot de passe Wi-Fi`.
static WIFI_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:(?:wi-?fi|wlan|wpa2?)\b[^\n]{0,40}?\b(?:key|cl[ée]|pass(?:word|phrase)?|",
        r"mot[ \t]+de[ \t]+passe|mdp)|(?:cl[ée]s?|mot[ \t]+de[ \t]+passe)[ \t]+(?:wi-?fi|wpa2?))\b"
    ))
    .expect("Wi-Fi keys compile")
});

/// Words that end a code run or are no Wi-Fi key, though they read as a group:
/// a sentence start or a polite close (`R6T3 Thanks`), or a status
/// (`Wi-Fi password: required`). Lowercase.
const PROSE_WORDS: &str = concat!(
    "thanks thank then please regards cheers hello sorry note also keep store merci bonjour ",
    "cordialement salut voici ensuite required optional unknown unchanged available attached ",
    "provided missing pending requis obligatoire facultatif inconnu disponible identique"
);

fn is_prose_word(word: &str) -> bool {
    PROSE_WORDS.split(' ').any(|w| w.eq_ignore_ascii_case(word))
}

/// `use VALUE as the password`: the value before its key.
static REVERSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\buse[ \t]+(\S{6,256}?)[ \t]+as[ \t]+(?:(?:the|your|my|our|their|a|an)[ \t]+)?",
        r"(?:new[ \t]+)?(?:password|passcode|passphrase|pin|api key)\b"
    ))
    .expect("reverse link compiles")
});

/// A cookie attribute after a `name=value` pair: the cue of a bare cookie.
static ATTR_CUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i);[ \t]?(?:path|domain|expires|max-age|samesite|httponly|secure)\b")
        .expect("cookie attribute cue compiles")
});

/// One cookie attribute or further pair, at the start of the rest of a value.
static ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)^;[ \t]?(?:expires=[a-z]{3},?[ \t][^;\n]{0,32}?gmt|",
        r"[a-z_][a-z0-9_.-]{0,63}(?:=[^;\s]{0,512})?)"
    ))
    .expect("cookie attribute compiles")
});

/// Words that link a key to its value.
const LINKS: &[&str] = &[
    "is",
    "was",
    "are",
    "were",
    "be",
    "as",
    "to",
    "use",
    "using",
    "with",
    "of",
    "like",
    "including",
    "value",
    "now",
    "equals",
    "en",
    "est",
    "etait",
    "était",
    "sera",
    "vaut",
];

#[derive(Clone, Copy, PartialEq)]
enum Class {
    Strong,
    Pin,
    Weak,
    Cookie,
}

fn class_of(key: &str) -> Class {
    let key = key.to_lowercase().replace(['\\', '_', '-'], " ");
    if key.starts_with("pin") || key.starts_with("code") && key.ends_with("pin") {
        Class::Pin
    } else if key.contains("cookie") {
        Class::Cookie
    } else if ["token", "tokens", "jeton", "jetons"].contains(&key.as_str()) {
        Class::Weak
    } else {
        Class::Strong
    }
}

/// Signs a password holds; quotes, markup (`~~` included), `=`, `/`, `-` and `_`
/// are left out, so a tag, an attribute or a hyphenated word is no password.
const SIGNS: &str = "!#$%&@^?+|{}";

/// An e-mail address, a URL, a date or a closing tag is not a secret value.
fn is_other_value(value: &str) -> bool {
    let date = value.as_bytes().get(..10).is_some_and(|head| {
        head.iter().enumerate().all(|(at, byte)| match at {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        })
    });
    date || value.contains("://")
        || value.contains("</")
        || value
            .split_once('@')
            .is_some_and(|(user, host)| !user.is_empty() && host.contains('.'))
}

/// Six or more characters: letters and digits, or a password sign with either.
fn strong(value: &str) -> bool {
    let count = value.chars().count();
    let alpha = value.chars().any(char::is_alphabetic);
    let digit = value.chars().any(|ch| ch.is_ascii_digit());
    let sign = value.chars().any(|ch| SIGNS.contains(ch));
    (6..=256).contains(&count)
        && (alpha && digit || sign && (alpha || digit))
        && !is_other_value(value)
}

/// Twelve or more characters of a token alphabet (letters, digits, `_.-+/=`),
/// with letters and digits: a bare `token` is often prose, and filler
/// such as `%41` or `&#x41;` is no token.
fn weak(value: &str) -> bool {
    value.chars().count() >= 12
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_.-+/=".contains(ch))
        && value.chars().any(char::is_alphabetic)
        && value.chars().any(|ch| ch.is_ascii_digit())
        && !is_other_value(value)
}

fn is_value(value: &str, class: Class) -> bool {
    match class {
        Class::Strong => strong(value),
        Class::Pin => {
            (4..=8).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
                || strong(value)
        }
        Class::Weak => weak(value),
        Class::Cookie => match value.split_once('=') {
            Some((name, rest)) if !name.is_empty() => {
                rest.chars().count() >= 16 || strong(rest) || weak(rest)
            }
            _ => weak(value),
        },
    }
}

const BRACKETS: &[char] = &['(', '«', '“', '‘', '[', '<'];
const ENDS: &[char] = &['.', ',', ';', ':', ')', '»', '”', '’', ']', '>'];
/// Quote and emphasis marks: trimmed only in pairs, since a password may start
/// or end with one.
const MARKS: &[char] = &['"', '\'', '`', '*'];

/// The value range of the word `text[start..end]`, its marks trimmed.
fn core(text: &str, start: usize, end: usize) -> (usize, usize) {
    let word = &text[start..end];
    let mut start = end - word.trim_start_matches(BRACKETS).len();
    let mut end = start + text[start..end].trim_end_matches(ENDS).len();
    while let Some(mark) = text[start..end]
        .chars()
        .next()
        .filter(|ch| MARKS.contains(ch))
    {
        if end - start < 2 || !text[start..end].ends_with(mark) {
            break;
        }
        start += 1;
        end = start + text[start..end - 1].trim_end_matches(ENDS).len();
    }
    (start, end)
}

/// The end of a cookie value's attributes and further pairs, from `at`.
fn attrs_end(text: &str, mut at: usize) -> usize {
    for _ in 0..MAX_ATTRS {
        let Some(found) = ATTR_RE.find(&text[at..]) else {
            break;
        };
        at += found.end();
    }
    at
}

/// The next word after `at` on the line: its range, or `None` at a line end, a
/// text end or a word too long to be a value.
fn next_word(text: &str, at: usize) -> Option<(usize, usize)> {
    let rest = bounded(text, at);
    let start = at + rest.len() - rest.trim_start_matches([' ', '\t']).len();
    let rest = bounded(text, start);
    if rest.is_empty() || rest.starts_with(['\n', '\r']) {
        return None;
    }
    let len = match rest.find(char::is_whitespace) {
        Some(len) => len,
        None if start + rest.len() == text.len() => rest.len(),
        None => return None,
    };
    (len <= MAX_WORD).then_some((start, start + len))
}

/// `text[at..]`, cut to `MAX_WORD + 1` bytes on a char boundary, so a read
/// never walks the whole text.
fn bounded(text: &str, at: usize) -> &str {
    let mut end = (at + MAX_WORD + 1).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[at..end]
}

/// Whether `word` links a key to the next word: a link word, or a word that ends
/// in `,`, `:`, `=` or `(`, or holds no letter or digit and one of them.
fn links(word: &str) -> bool {
    let bare = word.trim_matches(|ch: char| !ch.is_alphanumeric());
    if bare.is_empty() {
        return word.contains([':', '=', ',', '(', '-', '>', '：']);
    }
    let trimmed = word.trim_end_matches(['*', '_', '`', '"', '\'', ')']);
    trimmed.ends_with([',', ':', '=', '(', '：'])
        || LINKS.contains(&bare.to_lowercase().as_str()) && bare.len() == word.len()
}

/// The value after the key that ends at `key_end`, if one follows a link.
fn value_after(text: &str, key_end: usize, class: Class) -> Option<(usize, usize)> {
    let mut at = key_end;
    // The rest of the key's own word: a link glued to it (`pin:`, `key=X`), or a
    // compound (`password-protected`), which links nothing.
    let mut linked = true;
    let glued = bounded(text, at)
        .split(char::is_whitespace)
        .next()
        .unwrap_or("");
    if glued.starts_with(['.', '!', '?']) {
        return None;
    }
    if !glued.is_empty() {
        let mark_len = glued.len()
            - glued
                .trim_start_matches(['*', '_', '`', '"', '\'', ')', ':', '=', ',', '：'])
                .len();
        let marks = &glued[..mark_len];
        if marks.is_empty() || !marks.contains([':', '=', ',', '：']) && mark_len < glued.len() {
            linked = false;
            at += glued.len();
        } else {
            at += mark_len;
            if mark_len < glued.len() {
                let (start, end) = core(text, at, at + glued.len() - mark_len);
                if is_value(&text[start..end], class) {
                    return Some((start, end));
                }
                at += glued.len() - mark_len;
            }
        }
    }
    for _ in 0..MAX_WORDS {
        let (start, end) = next_word(text, at)?;
        let word = &text[start..end];
        let (value_start, value_end) = core(text, start, end);
        let opened = word.starts_with(BRACKETS) || word.starts_with(MARKS);
        if (linked || opened) && is_value(&text[value_start..value_end], class) {
            return Some((value_start, value_end));
        }
        if ["e.g.", "i.e.", "ex."].contains(&word.to_lowercase().as_str()) {
            linked = true;
            at = end;
            continue;
        }
        let ends = word
            .trim_end_matches(['"', '\'', ')', '*', '`'])
            .ends_with(['.', '!', '?']);
        if ends {
            return None;
        }
        linked = links(word);
        at = end;
    }
    None
}

/// Groups one run span holds at most, and its most bytes.
const MAX_RUN_GROUPS: usize = 16;
const MAX_RUN_BYTES: usize = 256;

/// State shared by all code fragments after one recovery-code cue.
#[derive(Default)]
struct RecoveryRun {
    group_len: Option<usize>,
    /// The run length, capped for same-shape letter-only continuations.
    groups: usize,
    confirmed: bool,
    digit_seen: bool,
    pending: Vec<(usize, usize)>,
}

impl RecoveryRun {
    fn reset(&mut self) {
        self.group_len = None;
        self.groups = 0;
        self.confirmed = false;
        self.digit_seen = false;
        self.pending.clear();
    }

    fn add_groups(&mut self, count: usize) {
        self.groups = self.groups.saturating_add(count).min(MAX_RUN_GROUPS);
    }

    fn active(&self) -> bool {
        self.group_len.is_some() && self.groups > 0
    }
}

/// The groups of one word of a code run (`7KQ2`, `7KQ2-9XZ1`, `7KQ2-` before a
/// line break), or `None` when a group is not 4 to 12 ASCII letters and digits
/// (3 to 12 inside a dashed word, so `blue-otter-472` is one Wi-Fi key).
fn run_groups(body: &str) -> Option<usize> {
    let body = body.strip_suffix('-').unwrap_or(body);
    let least = if body.contains('-') { 3 } else { 4 };
    let mut groups = 0;
    for group in body.split('-') {
        if !(least..=12).contains(&group.len()) || !group.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return None;
        }
        groups += 1;
    }
    Some(groups)
}

/// The code runs after an [`EXTRA_KEY_RE`] key ending at `from`: a line break
/// and one blank line may follow the key and its `:` or `,`, then a
/// [`code_run`] (`Recovery codes:\n7KQ2 9XZ1\nM4P8-R6T3`). Returns where the scan stopped,
/// so a later key inside the run is not read again (linear).
fn group_runs(
    text: &str,
    from: usize,
    recovery_codes: bool,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let bytes = text.as_bytes();
    let mut at = from;
    while matches!(bytes.get(at), Some(b' ' | b'\t')) {
        at += 1;
    }
    if matches!(bytes.get(at), Some(b':' | b'=' | b',')) {
        at += 1;
    } else if text[at..].starts_with('：') {
        at += '：'.len_utf8();
    }
    for _ in 0..2 {
        while matches!(bytes.get(at), Some(b' ' | b'\t')) {
            at += 1;
        }
        if text[at..].starts_with("\r\n") {
            at += 2;
        } else if text[at..].starts_with('\n') {
            at += 1;
        }
    }
    while matches!(bytes.get(at), Some(b' ' | b'\t')) {
        at += 1;
    }
    code_run(text, at, true, recovery_codes, recovery, spans).max(from)
}

/// One run of groups from `at`, joined by one space, a `-` or a line break. A
/// blank line, a lowercase word of five letters or more, a later word of
/// lowercase letters only (except a same-length recovery-code group within the
/// group cap), a [`PROSE_WORDS`] word (`R6T3 Thanks`), or any other word ends
/// the run; a `|` or `,` ends a word, and a line break ends the run unless
/// `lines`. Outside recovery cues, a run with no digit is no code. Each span
/// holds at most [`MAX_RUN_GROUPS`] groups and [`MAX_RUN_BYTES`] bytes, and a
/// longer run goes on in a next span. Returns where the run ended.
fn code_run(
    text: &str,
    mut at: usize,
    lines: bool,
    recovery_codes: bool,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    if recovery_codes {
        return recovery_code_run(text, at, lines, !lines, recovery, spans);
    }
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let (mut start, mut end, mut groups, mut digit, mut first) = (at, at, 0, false, true);
    loop {
        let len = bytes[at..]
            .iter()
            .take(MAX_RUN_BYTES + 1)
            .take_while(|b| !b.is_ascii_whitespace() && !matches!(b, b'|' | b','))
            .count();
        if len == 0 || len > MAX_RUN_BYTES || !text.is_char_boundary(at + len) {
            break;
        }
        let word = &text[at..at + len];
        let body = word.trim_end_matches(['.', ',', ';', ')']);
        let lower = !body.is_empty() && body.bytes().all(|b| b.is_ascii_lowercase());
        let Some(count) = run_groups(body) else { break };
        if lower && (body.len() >= 5 || !first) {
            break;
        }
        if is_prose_word(body) {
            break;
        }
        if groups + count > MAX_RUN_GROUPS || at + body.len() - start > MAX_RUN_BYTES {
            if end > start {
                found.push((start, end));
            }
            (start, groups) = (at, 0);
        }
        groups += count;
        digit |= body.bytes().any(|b| b.is_ascii_digit());
        end = at + body.len();
        at += len;
        first = false;
        if body.len() < word.len() {
            break;
        }
        let next = if bytes.get(at) == Some(&b' ') {
            1
        } else if lines && text[at..].starts_with("\r\n") {
            2
        } else if lines && bytes.get(at) == Some(&b'\n') {
            1
        } else {
            break;
        };
        if bytes.get(at + next).is_none_or(u8::is_ascii_whitespace) {
            break;
        }
        at += next;
    }
    if end > start {
        found.push((start, end));
    }
    if digit {
        spans.extend(found);
    }
    end
}

/// Reads recovery-code fragments while retaining their shape across spaces,
/// comma cells, and list items. Three same-length letters-only groups confirm
/// an otherwise digitless run; until then their spans stay bounded in `pending`.
fn recovery_code_run(
    text: &str,
    mut at: usize,
    lines: bool,
    strict_shape: bool,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let bytes = text.as_bytes();
    let mut end = at;
    loop {
        let len = bytes[at..]
            .iter()
            .take(MAX_RUN_BYTES + 1)
            .take_while(|b| !b.is_ascii_whitespace() && !matches!(b, b'|' | b','))
            .count();
        if len == 0 || len > MAX_RUN_BYTES || !text.is_char_boundary(at + len) {
            break;
        }
        let word = &text[at..at + len];
        let body = word.trim_end_matches(['.', ',', ';', ')']);
        let Some(count) = run_groups(body) else {
            recovery.reset();
            break;
        };
        if is_prose_word(body) {
            recovery.reset();
            break;
        }

        let parts = body.strip_suffix('-').unwrap_or(body);
        let group_len = parts.split('-').next().map_or(0, str::len);
        let same_part_lengths = parts.split('-').all(|group| group.len() == group_len);
        let letters_only = same_part_lengths
            && !parts.is_empty()
            && parts
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || byte == b'-');
        let lower = !body.is_empty() && body.bytes().all(|byte| byte.is_ascii_lowercase());
        let has_digit = body.bytes().any(|byte| byte.is_ascii_digit());
        let bounded_letters = letters_only && (!recovery.digit_seen || lower || strict_shape);
        if bounded_letters && recovery.groups.saturating_add(count) > MAX_RUN_GROUPS {
            break;
        }

        if letters_only {
            if recovery.group_len.is_none() {
                recovery.group_len = Some(group_len);
            }
            let same_length = recovery.group_len == Some(group_len);
            if !recovery.confirmed && !same_length {
                recovery.reset();
                break;
            }
            if recovery.confirmed && (!recovery.digit_seen || lower || strict_shape) && !same_length
            {
                recovery.reset();
                break;
            }
            // Uppercase and mixed-case letter groups already continued a
            // digit-backed run before this recovery-specific extension.
            recovery.add_groups(count);
            let group_end = at + body.len();
            if recovery.confirmed {
                spans.push((at, group_end));
            } else {
                recovery.pending.push((at, group_end));
                if recovery.groups >= 3 {
                    recovery.confirmed = true;
                    spans.append(&mut recovery.pending);
                }
            }
            end = group_end;
        } else {
            if !recovery.confirmed
                && recovery
                    .group_len
                    .is_some_and(|expected| expected != group_len)
            {
                recovery.reset();
            }
            recovery.group_len.get_or_insert(group_len);
            recovery.add_groups(count);
            if has_digit {
                recovery.confirmed = true;
                recovery.digit_seen = true;
                spans.append(&mut recovery.pending);
            }
            if recovery.confirmed {
                spans.push((at, at + body.len()));
            } else {
                recovery.reset();
                break;
            }
            end = at + body.len();
        }

        at += len;
        if body.len() < word.len() {
            recovery.reset();
            break;
        }
        let next = if bytes.get(at) == Some(&b' ') {
            1
        } else if lines && text[at..].starts_with("\r\n") {
            2
        } else if lines && bytes.get(at) == Some(&b'\n') {
            1
        } else {
            break;
        };
        if bytes.get(at + next).is_none_or(u8::is_ascii_whitespace) {
            break;
        }
        at += next;
    }
    end
}

/// Bullets a list item of codes may start with.
const BULLETS: &[char] = &['-', '*', '+', '•', '◦', '‣', '–'];

/// The length of the list marker that starts `item` (`- `, `• `, `1. `, `1) `),
/// the blanks after it and a checkbox (`[ ] `), or `None`.
fn marker(item: &str) -> Option<usize> {
    let digits = item.bytes().take(4).take_while(u8::is_ascii_digit).count();
    let numbered = matches!(item.as_bytes().get(digits), Some(b'.' | b')'));
    let bullet = item.chars().next().filter(|ch| BULLETS.contains(ch));
    let mark = match digits {
        1..=3 if numbered => digits + 1,
        _ => bullet?.len_utf8(),
    };
    let rest = &item[mark..];
    let gap = rest.len() - rest.trim_start_matches([' ', '\t']).len();
    let rest = &rest[gap..];
    let boxed = ["[ ] ", "[x] ", "[X] "].iter().any(|b| rest.starts_with(b));
    (gap > 0).then_some(mark + gap + if boxed { 4 } else { 0 })
}

/// The [`code_run`] of each cell of `line`, which starts at `at`: after each
/// `|`, tab, and comma with no blank after it, or a comma after an active
/// recovery-code run. Returns where the last run ended, or `None` with no cell.
fn cells(
    text: &str,
    at: usize,
    line: &str,
    recovery_codes: bool,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> Option<usize> {
    let mut done = None;
    for (cut, sep) in line.match_indices(['|', '\t', ',']) {
        let cell = &line[cut + 1..];
        let blank = cell.len() - cell.trim_start_matches([' ', '\t']).len();
        let cue_comma = sep == ","
            && line[..cut]
                .trim_matches([' ', '\t', ':', '=', ',', '：'])
                .is_empty();
        let comma_cell = sep == ","
            && !cue_comma
            && (blank == 0 && !cell.is_empty() || recovery_codes && recovery.active());
        if sep != "," || comma_cell {
            done = done.max(Some(code_run(
                text,
                at + cut + 1 + blank,
                false,
                recovery_codes,
                recovery,
                spans,
            )));
        }
    }
    done
}

/// SECRET-RECALL-2: the code rows after a recovery-code key ending at `from`.
/// In a table row (`| Recovery codes | 7KQ2-9XZ1 |`) the [`cells`] after the
/// key are read; when the key ends its line or a `:` header (`Backup codes:`),
/// each next list item (`- `, `• `, `1. `, `- [ ] `) or row of cells is read
/// too. One blank line may follow the key; a later one or any other line ends
/// the rows. Returns where the scan stopped (linear: a row is read once, a key
/// line at most [`MAX_WORD`] bytes).
fn row_runs(
    text: &str,
    from: usize,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let head = bounded(text, from);
    let (head, ends) = head
        .split_once('\n')
        .map_or((head, false), |(line, _)| (line, true));
    let bare = head.trim().trim_matches(['*', '_', '#']);
    let done = cells(text, from, head, true, recovery, spans);
    if done.is_none() && !(bare.is_empty() || bare.ends_with([':', '：'])) {
        return from;
    }
    let mut done = done.unwrap_or(from);
    if !ends {
        return done;
    }
    let (mut at, mut first) = (from + head.len() + 1, true);
    while at < text.len() {
        let line_end = text[at..].find('\n').map_or(text.len(), |len| at + len);
        let line = text[at..line_end].trim_end_matches('\r');
        let lead = line.len() - line.trim_start().len();
        let item = marker(&line[lead..]);
        let celled = cells(text, at, line, true, recovery, spans);
        if item.is_none() && celled.is_none() && !(first && line.trim().is_empty()) {
            break;
        }
        if let Some(skip) = item {
            code_run(text, at + lead + skip, false, true, recovery, spans);
        }
        (done, first) = (line_end, false);
        at = line_end + 1;
    }
    done
}

/// SECRET-RECALL-2: a letters-only Wi-Fi key right after its [`WIFI_KEY_RE`]
/// key and a `:`, `=`, `is` or `est` (`Wi-Fi key: blueotterriver`), on the
/// key's line or the next: 8 to 63 letters, the length of a WPA passphrase, not
/// a [`PROSE_WORDS`] status nor `ask…`/`see…`, and after `is` no `-ed` or `-ing`
/// verb (`is changing`). The value position is the cue, so no digit is needed.
fn wifi_word(text: &str, from: usize) -> Option<(usize, usize)> {
    let rest = bounded(text, from);
    let trimmed = rest.trim_start_matches([' ', '\t']);
    let word = ["is ", "est "].iter().find_map(|w| trimmed.strip_prefix(w));
    let linked = word.or_else(|| trimmed.strip_prefix([':', '=', '：']))?;
    let linked = linked.trim_start_matches([' ', '\t']);
    let next = linked.strip_prefix("\r\n").or(linked.strip_prefix('\n'));
    let (start, word_end) = next_word(text, from + rest.len() - next.unwrap_or(linked).len())?;
    let (start, end) = core(text, start, word_end);
    let value = &text[start..end];
    let verb = word.is_some() && (value.ends_with("ed") || value.ends_with("ing"));
    let lower = value.to_lowercase();
    let prose = is_prose_word(value) || lower.starts_with("ask") || lower.starts_with("see");
    let letters = value.chars().all(char::is_alphabetic) && !prose && !verb;
    ((8..=63).contains(&value.chars().count()) && letters).then_some((start, end))
}

/// The secret spans of prose links, escaped keys and cookies in `text`.
pub(crate) fn prose_scan(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut reach = 0;
    for found in KEY_RE.captures_iter(text) {
        let Some(key) = found.get(1) else { continue };
        if key.start() < reach {
            continue;
        }
        let class = class_of(key.as_str());
        reach = key.end();
        if let Some((start, mut end)) = value_after(text, key.end(), class) {
            if class == Class::Cookie || text[start..end].contains('=') {
                end = attrs_end(text, end);
            }
            spans.push((start, end));
            reach = end;
        }
    }
    let mut reach = 0;
    for key in EXTRA_KEY_RE.find_iter(text) {
        if let Some(span) = value_after(text, key.end(), Class::Strong) {
            spans.push(span);
        }
        if key.start() >= reach {
            let recovery_codes = key.as_str().to_ascii_lowercase().contains("code");
            let mut recovery = RecoveryRun::default();
            reach = group_runs(text, key.end(), recovery_codes, &mut recovery, &mut spans);
            if recovery_codes {
                reach = reach.max(row_runs(text, key.end(), &mut recovery, &mut spans));
            }
        }
    }
    for key in WIFI_KEY_RE.find_iter(text) {
        spans.extend(wifi_word(text, key.end()));
    }
    for found in REVERSE_RE.captures_iter(text) {
        if let Some(value) = found.get(1) {
            let (start, end) = core(text, value.start(), value.end());
            if strong(&text[start..end]) {
                spans.push((start, end));
            }
        }
    }
    let mut reach = 0;
    for cue in ATTR_CUE_RE.find_iter(text) {
        if cue.start() < reach {
            continue;
        }
        let mut low = cue.start().saturating_sub(MAX_WORD);
        while !text.is_char_boundary(low) {
            low += 1;
        }
        let before = &text[low..cue.start()];
        let space = before
            .char_indices()
            .rev()
            .find(|(_, ch)| ch.is_whitespace());
        let from = match space {
            Some((at, ch)) => low + at + ch.len_utf8(),
            None if low == 0 => 0,
            None => continue,
        };
        let (start, _) = core(text, from, cue.start());
        if start < cue.start() && is_value(&text[start..cue.start()], Class::Cookie) {
            let end = attrs_end(text, cue.start());
            spans.push((start, end));
            reach = end;
        }
    }
    // The key scan and the cookie cue may find the same value: keep it once.
    spans.sort_unstable();
    spans.dedup();
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hidden(text: &str) -> Vec<&str> {
        prose_scan(text)
            .into_iter()
            .map(|(s, e)| &text[s..e])
            .collect()
    }

    #[test]
    fn a_value_after_a_prose_link_is_found() {
        let value = format!("Wq5{}", "$wDf8n");
        let text = format!("I changed the admin password on the NAS to {value} today.");
        assert_eq!(hidden(&text), [value.as_str()]);
        assert_eq!(
            hidden("Please enter your PIN, which is 552190, in the box."),
            ["552190"]
        );
    }

    #[test]
    fn prose_after_a_link_stays_clear() {
        for text in [
            "the password is required",
            "set it to default",
            "The key, in short, is patience.",
            "password-protected files are opened with care",
            "theme=dark; Path=/",
        ] {
            assert!(hidden(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn a_cookie_takes_its_attributes() {
        let value = format!("sid={}", "Vt9Rw4Zp8Kx3Nb45");
        let text = format!("the http cookie {value}; Path=/; HttpOnly in the call");
        assert_eq!(
            hidden(&text),
            [format!("{value}; Path=/; HttpOnly").as_str()]
        );
    }
}
