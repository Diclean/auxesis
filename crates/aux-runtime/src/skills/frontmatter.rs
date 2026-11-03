//! A minimal YAML reader for skill and agent front matter.
//!
//! The skills contract moved out of this repository (see `docs/README.md`).
//! It fixes the shapes the loader accepts: block and flow mappings, block and
//! flow sequences, and scalars. This is a deliberate subset, **not** a YAML
//! implementation. Any construct outside it is a parse error, so a file the
//! loader does not understand fails to load instead of being silently misread.

use std::fmt;

/// One parsed front-matter value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`, `~` or an empty value.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// An integer scalar.
    Int(i64),
    /// A floating-point scalar.
    Float(f64),
    /// A string scalar (bare or quoted).
    Str(String),
    /// A sequence (`- item` or `[a, b]`).
    List(Vec<Value>),
    /// A mapping (`key: value` or `{a: b}`), in file order.
    Map(Vec<(String, Value)>),
}

impl Value {
    /// A short name for the value's kind, for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Int(_) => "integer",
            Value::Float(_) => "number",
            Value::Str(_) => "string",
            Value::List(_) => "sequence",
            Value::Map(_) => "mapping",
        }
    }

    /// The string inside a [`Value::Str`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(value) => Some(value),
            _ => None,
        }
    }

    /// The boolean inside a [`Value::Bool`].
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// The entries of a [`Value::Map`].
    pub fn as_map(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// The items of a [`Value::List`].
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(items) => Some(items),
            _ => None,
        }
    }

    /// The value of `key` when this is a mapping.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// True for [`Value::Null`].
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// A front-matter parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontMatterError(pub String);

impl fmt::Display for FrontMatterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FrontMatterError {}

fn error(message: impl Into<String>) -> FrontMatterError {
    FrontMatterError(message.into())
}

/// Split `text` into its `---` front matter and the body that follows it.
///
/// The front matter must start on the first line and close with a `---` line;
/// the body is every line after the closer.
pub fn parse(text: &str) -> Result<(Value, String), FrontMatterError> {
    let lines: Vec<&str> = text.split('\n').collect();
    let first = lines.first().copied().unwrap_or("");
    if first.trim_end_matches('\r').trim() != "---" {
        return Err(error("missing `---` front matter opener"));
    }
    let close = lines
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, line)| line.trim_end_matches('\r').trim() == "---")
        .map(|(index, _)| index)
        .ok_or_else(|| error("missing closing `---` for front matter"))?;
    let prepared = prepare(&lines[1..close])?;
    let value = Parser::new(prepared).parse()?;
    let body = lines[close + 1..].join("\n");
    Ok((value, body))
}

/// One significant front-matter line: its indentation and content, with the
/// trailing comment removed.
struct Line {
    indent: usize,
    text: String,
}

fn prepare(raw_lines: &[&str]) -> Result<Vec<Line>, FrontMatterError> {
    let mut lines = Vec::new();
    for raw in raw_lines {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let mut indent = 0usize;
        for ch in raw.chars() {
            match ch {
                ' ' => indent += 1,
                '\t' => return Err(error("tab indentation is not supported")),
                _ => break,
            }
        }
        let content = strip_comment(&raw[indent..]).trim_end();
        if content.trim().is_empty() {
            continue;
        }
        lines.push(Line {
            indent,
            text: content.to_string(),
        });
    }
    Ok(lines)
}

/// Remove a trailing `# comment` that is outside quotes.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_double {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_double = false;
            }
        } else if in_single {
            if byte == b'\'' {
                if index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
                    index += 1;
                } else {
                    in_single = false;
                }
            }
        } else {
            match byte {
                b'"' => in_double = true,
                b'\'' => in_single = true,
                b'#' if index == 0 || bytes[index - 1].is_ascii_whitespace() => {
                    return &line[..index];
                }
                _ => {}
            }
        }
        index += 1;
    }
    line
}

/// Maximum nesting depth accepted in front matter, so a hostile file cannot
/// exhaust the stack.
const MAX_NESTING_DEPTH: usize = 32;

struct Parser {
    lines: Vec<Line>,
    pos: usize,
}

impl Parser {
    fn new(lines: Vec<Line>) -> Self {
        Parser { lines, pos: 0 }
    }

    fn parse(mut self) -> Result<Value, FrontMatterError> {
        if self.lines.is_empty() {
            return Ok(Value::Map(Vec::new()));
        }
        let indent = self.lines[0].indent;
        let value = self.parse_block(indent, 0)?;
        if self.pos < self.lines.len() {
            return Err(error(format!(
                "unexpected indentation near `{}`",
                self.lines[self.pos].text
            )));
        }
        Ok(value)
    }

    fn parse_block(&mut self, indent: usize, depth: usize) -> Result<Value, FrontMatterError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(error("front matter nesting is too deep"));
        }
        let text = &self.lines[self.pos].text;
        if text == "-" || text.starts_with("- ") {
            self.parse_sequence(indent, depth)
        } else {
            self.parse_mapping(indent, depth)
        }
    }

    fn parse_mapping(&mut self, indent: usize, depth: usize) -> Result<Value, FrontMatterError> {
        let mut entries: Vec<(String, Value)> = Vec::new();
        while self.pos < self.lines.len() {
            let line = &self.lines[self.pos];
            if line.indent < indent {
                break;
            }
            if line.indent > indent {
                return Err(error(format!(
                    "unexpected indentation near `{}`",
                    line.text
                )));
            }
            let text = line.text.clone();
            if text == "-" || text.starts_with("- ") {
                return Err(error("expected a mapping key, found a sequence item"));
            }
            let colon = find_key_colon(&text)
                .ok_or_else(|| error(format!("mapping entry `{text}` has no `:`")))?;
            let key = unquote_key(text[..colon].trim())?;
            if key.is_empty() {
                return Err(error("mapping key must not be empty"));
            }
            let rest = text[colon + 1..].to_string();
            self.pos += 1;
            let value = self.parse_value(&rest, indent, depth)?;
            if entries.iter().any(|(name, _)| *name == key) {
                return Err(error(format!("duplicate key `{key}`")));
            }
            entries.push((key, value));
        }
        Ok(Value::Map(entries))
    }

    fn parse_value(
        &mut self,
        rest: &str,
        indent: usize,
        depth: usize,
    ) -> Result<Value, FrontMatterError> {
        let rest = rest.trim();
        if rest.is_empty() {
            if self.pos < self.lines.len() && self.lines[self.pos].indent > indent {
                let child = self.lines[self.pos].indent;
                return self.parse_block(child, depth + 1);
            }
            return Ok(Value::Null);
        }
        parse_inline(rest, depth)
    }

    fn parse_sequence(&mut self, indent: usize, depth: usize) -> Result<Value, FrontMatterError> {
        let mut items = Vec::new();
        while self.pos < self.lines.len() {
            let line = &self.lines[self.pos];
            if line.indent < indent {
                break;
            }
            if line.indent > indent {
                return Err(error(format!(
                    "unexpected indentation near `{}`",
                    line.text
                )));
            }
            let text = line.text.clone();
            let Some(rest) = text.strip_prefix('-') else {
                break;
            };
            if !rest.is_empty() && !rest.starts_with(' ') {
                return Err(error("sequence items must start with `- `"));
            }
            let rest = rest.trim_start().to_string();
            self.pos += 1;
            if rest.is_empty() {
                if self.pos < self.lines.len() && self.lines[self.pos].indent > indent {
                    let child = self.lines[self.pos].indent;
                    items.push(self.parse_block(child, depth + 1)?);
                } else {
                    items.push(Value::Null);
                }
                continue;
            }
            if let Some(colon) = find_key_colon(&rest) {
                // `- key: value`, optionally followed by more keys at a deeper
                // indent belonging to the same item.
                let key = unquote_key(rest[..colon].trim())?;
                let value_rest = rest[colon + 1..].to_string();
                let first = self.parse_value(&value_rest, indent, depth)?;
                let mut entries = vec![(key, first)];
                if self.pos < self.lines.len() && self.lines[self.pos].indent > indent {
                    let child = self.lines[self.pos].indent;
                    if let Value::Map(more) = self.parse_mapping(child, depth + 1)? {
                        for (name, value) in more {
                            if entries.iter().any(|(existing, _)| *existing == name) {
                                return Err(error(format!("duplicate key `{name}`")));
                            }
                            entries.push((name, value));
                        }
                    }
                }
                items.push(Value::Map(entries));
            } else {
                items.push(parse_inline(&rest, depth)?);
            }
        }
        Ok(Value::List(items))
    }
}

/// Parse an inline (single-line) value: flow map, flow list, quoted string or
/// bare scalar.
fn parse_inline(text: &str, depth: usize) -> Result<Value, FrontMatterError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(error("flow nesting is too deep"));
    }
    let text = text.trim();
    if text.is_empty() {
        return Ok(Value::Null);
    }
    if let Some(inner) = text.strip_prefix('{') {
        let inner = inner
            .strip_suffix('}')
            .ok_or_else(|| error("unterminated flow mapping"))?;
        let mut entries = Vec::new();
        for part in split_top_level(inner, ',')? {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let colon = find_key_colon(part)
                .ok_or_else(|| error(format!("flow mapping entry `{part}` has no `:`")))?;
            let key = unquote_key(part[..colon].trim())?;
            let value = parse_inline(part[colon + 1..].trim(), depth + 1)?;
            if entries.iter().any(|(name, _)| *name == key) {
                return Err(error(format!("duplicate key `{key}`")));
            }
            entries.push((key, value));
        }
        return Ok(Value::Map(entries));
    }
    if let Some(inner) = text.strip_prefix('[') {
        let inner = inner
            .strip_suffix(']')
            .ok_or_else(|| error("unterminated flow sequence"))?;
        let mut items = Vec::new();
        for part in split_top_level(inner, ',')? {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            items.push(parse_inline(part, depth + 1)?);
        }
        return Ok(Value::List(items));
    }
    if text.starts_with('"') {
        return Ok(Value::Str(parse_double_quoted(text)?));
    }
    if text.starts_with('\'') {
        return Ok(Value::Str(parse_single_quoted(text)?));
    }
    Ok(parse_scalar(text))
}

/// Split `text` on `separator` at the top level, ignoring separators inside
/// quotes or flow brackets.
fn split_top_level(text: &str, separator: char) -> Result<Vec<&str>, FrontMatterError> {
    let bytes = text.as_bytes();
    let separator = separator as u8;
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_double {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_double = false;
            }
        } else if in_single {
            if byte == b'\'' {
                if index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
                    index += 1;
                } else {
                    in_single = false;
                }
            }
        } else {
            match byte {
                b'"' => in_double = true,
                b'\'' => in_single = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                _ if byte == separator && depth == 0 => {
                    parts.push(&text[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    if in_single || in_double {
        return Err(error("unterminated quoted string"));
    }
    if depth != 0 {
        return Err(error("unbalanced flow brackets"));
    }
    parts.push(&text[start..]);
    Ok(parts)
}

/// Find the first `:` that separates a mapping key from its value: outside
/// quotes and flow brackets, and followed by whitespace or the end of input.
fn find_key_colon(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut depth = 0i32;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_double {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_double = false;
            }
        } else if in_single {
            if byte == b'\'' {
                if index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
                    index += 1;
                } else {
                    in_single = false;
                }
            }
        } else {
            match byte {
                b'"' => in_double = true,
                b'\'' => in_single = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                b':' if depth == 0 && (index + 1 >= bytes.len() || bytes[index + 1] == b' ') => {
                    return Some(index);
                }
                _ => {}
            }
        }
        index += 1;
    }
    None
}

fn unquote_key(key: &str) -> Result<String, FrontMatterError> {
    if key.starts_with('"') {
        return parse_double_quoted(key);
    }
    if key.starts_with('\'') {
        return parse_single_quoted(key);
    }
    Ok(key.to_string())
}

fn parse_double_quoted(text: &str) -> Result<String, FrontMatterError> {
    let inner = text
        .strip_prefix('"')
        .ok_or_else(|| error("expected a double-quoted string"))?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                let rest: String = chars.collect();
                if rest.trim().is_empty() {
                    return Ok(out);
                }
                return Err(error("unexpected text after a closing quote"));
            }
            '\\' => {
                let escape = chars
                    .next()
                    .ok_or_else(|| error("dangling escape in a quoted string"))?;
                match escape {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            }
            other => out.push(other),
        }
    }
    Err(error("unterminated double-quoted string"))
}

fn parse_single_quoted(text: &str) -> Result<String, FrontMatterError> {
    let inner = text
        .strip_prefix('\'')
        .ok_or_else(|| error("expected a single-quoted string"))?;
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
                out.push('\'');
            } else {
                let rest: String = chars.collect();
                if rest.trim().is_empty() {
                    return Ok(out);
                }
                return Err(error("unexpected text after a closing quote"));
            }
        } else {
            out.push(ch);
        }
    }
    Err(error("unterminated single-quoted string"))
}

fn parse_scalar(text: &str) -> Value {
    match text {
        "" | "null" | "Null" | "NULL" | "~" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        _ => {
            if let Ok(value) = text.parse::<i64>() {
                return Value::Int(value);
            }
            let numeric = text.chars().any(|ch| ch.is_ascii_digit())
                && text
                    .chars()
                    .all(|ch| ch.is_ascii_digit() || matches!(ch, '+' | '-' | '.' | 'e' | 'E'));
            if numeric {
                if let Ok(value) = text.parse::<f64>() {
                    return Value::Float(value);
                }
            }
            Value::Str(text.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map<'a>(value: &'a Value, key: &str) -> &'a Value {
        value.get(key).expect("key present")
    }

    #[test]
    fn parses_the_contract_shapes() {
        let text = "\
---
name: send-invite                 # [a-z0-9-]{1,40}; unique per agent
version: 1
command: invite
trigger:
  manual: true
  schedule: null
  on: null
tools: [google.calendar.create_event, google.gmail.send]
inputs:
  person:   { tier: H }
  duration: { type: duration, default: 30m }
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
body line
";
        let (value, body) = parse(text).unwrap();
        assert_eq!(map(&value, "name").as_str(), Some("send-invite"));
        assert_eq!(map(&value, "version").as_str(), None);
        assert_eq!(map(&value, "version"), &Value::Int(1));
        assert_eq!(map(&value, "tools").as_list().unwrap().len(), 2);
        let trigger = map(&value, "trigger");
        assert_eq!(map(trigger, "manual").as_bool(), Some(true));
        assert!(map(trigger, "schedule").is_null());
        let inputs = map(&value, "inputs");
        assert_eq!(map(map(inputs, "person"), "tier").as_str(), Some("H"));
        let duration = map(inputs, "duration");
        assert_eq!(map(duration, "type").as_str(), Some("duration"));
        assert_eq!(map(duration, "default").as_str(), Some("30m"));
        assert_eq!(body, "body line\n");
    }

    #[test]
    fn parses_block_sequences_and_numbers() {
        let text = "\
---
tools:
  - google.gmail.search
  - google.gmail.send
budget: { daily_usd: 2.00 }
channels: [mac, telegram]
---
";
        let (value, _) = parse(text).unwrap();
        assert_eq!(map(&value, "tools").as_list().unwrap().len(), 2);
        assert_eq!(
            map(&value, "budget").get("daily_usd"),
            Some(&Value::Float(2.0))
        );
        assert_eq!(map(&value, "channels").as_list().unwrap().len(), 2);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(parse("no front matter").is_err());
        assert!(parse("---\nname: x\n").is_err());
        assert!(parse("---\nname: x\nname: y\n---\n").is_err());
        assert!(parse("---\nname: \"x\n---\n").is_err());
    }

    #[test]
    fn comments_are_stripped_but_not_inside_quotes() {
        assert_eq!(strip_comment("version: 1 # note"), "version: 1 ");
        assert_eq!(
            strip_comment("cron: \"0 9 * * 1\" # daily"),
            "cron: \"0 9 * * 1\" "
        );
        assert_eq!(strip_comment("x: a#b"), "x: a#b");
    }

    #[test]
    fn deeply_nested_flow_is_refused() {
        let deep = format!(
            "---\nvalue: {}1{}\n---\n",
            "[".repeat(MAX_NESTING_DEPTH + 5),
            "]".repeat(MAX_NESTING_DEPTH + 5)
        );
        let err = parse(&deep).unwrap_err();
        assert!(err.to_string().contains("too deep"), "{err}");
    }

    #[test]
    fn deeply_nested_blocks_are_refused() {
        let mut text = String::from("---\n");
        for level in 0..MAX_NESTING_DEPTH + 5 {
            text.push_str(&" ".repeat(level));
            text.push_str(&format!("k{level}:\n"));
        }
        text.push_str("---\n");
        let err = parse(&text).unwrap_err();
        assert!(err.to_string().contains("too deep"), "{err}");
    }
}
