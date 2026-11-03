//! E-mail address recogniser: a pattern plus an RFC-822-style structural check.

use std::sync::LazyLock;

use regex::Regex;

use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Base score for a structurally valid address.
pub const SCORE: f32 = 0.7;
/// Score for something that looks like an address but fails the strict
/// structural check (for example a leading dot in the local part). Detection
/// fails closed: it is masked at a lower score rather than left in clear.
pub const QUESTIONABLE_SCORE: f32 = 0.6;

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Unicode letters and digits in both the local part and the domain, so
    // IDN domains and non-ASCII local parts are still found (P1-4).
    Regex::new(r"(?i)[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.[\p{L}]{2,63}")
        .expect("email regex compiles")
});

/// Finds structurally valid e-mail addresses.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmailRecognizer;

impl EmailRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for EmailRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Email]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        // Fullwidth letters, digits and `＠` are folded before the scan.
        let normalized = NormalizedText::new(text, false);
        let body = normalized.text();
        let mut spans = Vec::new();
        let mut cursor = 0usize;
        while cursor < body.len() {
            let Some(found) = EMAIL_RE.find_at(body, cursor) else {
                break;
            };
            let (start, end) = (found.start(), found.end());
            if has_email_boundaries(body, start, end) {
                // Fail toward masking: an address-shaped match is always
                // reported; the structural check only lowers the score.
                let score = if valid_email(&body[start..end]) {
                    SCORE
                } else {
                    QUESTIONABLE_SCORE
                };
                if let Some((start, end)) = normalized.to_original(start, end) {
                    spans.push(Span::new(EntityKind::Email, start, end, score, "email"));
                }
                cursor = end;
            } else {
                // A rejected match is retried from the next position (P2-4).
                // When the *right* side rejected the match, every start inside
                // the same local-part run would produce the same bad tail, so
                // the whole `[\p{L}\p{N}._%+\-]+` run is skipped at once: that
                // is what keeps an adversarial `a.a.…a@example.com¼` linear.
                // A left-side rejection only needs one step, so the address
                // that follows a separator (`a@x.invalid.b@y.invalid`) is still
                // tried from its own start.
                let next = if right_boundary_ok(body, end) {
                    if body[start..]
                        .chars()
                        .next()
                        .is_some_and(char::is_alphanumeric)
                    {
                        skip_alphanumeric_run(body, start)
                    } else {
                        next_char_boundary(body, start)
                    }
                } else {
                    skip_local_part_run(body, start)
                };
                cursor = next.max(start + 1);
            }
        }
        spans
    }

    fn name(&self) -> &'static str {
        "email"
    }
}

/// Whether a match sits at an address boundary.
///
/// The left side rejects only an alphanumeric character, so the address that
/// follows a `.`/`-` separator (`a@x.invalid.b@y.invalid`) is accepted after the
/// retry. On the right, a following digit is accepted too: the TLD of
/// `jean.dupont@example.invalid2026` is masked even though a digit follows.
fn has_email_boundaries(text: &str, start: usize, end: usize) -> bool {
    left_boundary_ok(text, start) && right_boundary_ok(text, end)
}

/// Whether the byte before `start` allows an address to begin there.
fn left_boundary_ok(text: &str, start: usize) -> bool {
    text[..start]
        .chars()
        .next_back()
        .is_none_or(|ch| !ch.is_alphanumeric())
}

/// Whether the byte after `end` allows an address to finish there.
fn right_boundary_ok(text: &str, end: usize) -> bool {
    text[end..]
        .chars()
        .next()
        .is_none_or(|ch| (!ch.is_alphanumeric() && ch != '@') || ch.is_ascii_digit())
}

/// The byte offset one character after `index`.
fn next_char_boundary(text: &str, index: usize) -> usize {
    text[index..]
        .chars()
        .next()
        .map(|ch| index + ch.len_utf8())
        .unwrap_or(text.len())
}

/// The byte offset at the end of the alphanumeric run that starts at `index`.
fn skip_alphanumeric_run(text: &str, index: usize) -> usize {
    let mut cursor = index;
    for ch in text[index..].chars() {
        if !ch.is_alphanumeric() {
            break;
        }
        cursor += ch.len_utf8();
    }
    cursor
}

/// The byte offset at the end of the e-mail local-part run that starts at
/// `index`: exactly the characters `EMAIL_RE`'s local part accepts, so one
/// skipped run covers every start that would share the same rejected tail.
fn skip_local_part_run(text: &str, index: usize) -> usize {
    let mut cursor = index;
    for ch in text[index..].chars() {
        if !(ch.is_alphanumeric() || "._%+-".contains(ch)) {
            break;
        }
        cursor += ch.len_utf8();
    }
    cursor
}

/// A deliberately strict check: one `@`, an RFC dot-atom local part and a
/// dotted host whose last label is alphabetic. Letters and digits may be of
/// any script (Unicode local parts and IDN domains, P1-4).
pub(crate) fn valid_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if local.is_empty() || local.chars().count() > 64 {
        return false;
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    if !local
        .chars()
        .all(|ch| ch.is_alphanumeric() || "._%+-".contains(ch))
    {
        return false;
    }
    if domain.is_empty() || domain.len() > 255 || !domain.contains('.') {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.chars().count() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|ch| ch.is_alphanumeric() || ch == '-') {
            return false;
        }
    }
    let tld = labels.last().copied().unwrap_or("");
    let tld_len = tld.chars().count();
    (2..=63).contains(&tld_len) && tld.chars().all(|ch| ch.is_alphabetic())
}

/// The `@` of an address written out: `[at]`, `(at)`, `arobase`, a spaced `@`,
/// or the bare word `at` (group 1), which needs more proof.
static SPELLED_AT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\s{0,4}[\[({<]\s{0,2}(?:at|@|arobase)\s{0,2}[\])}>]\s{0,4}|\s{1,4}(?:(at)|arobase)\s{1,4}|\s{1,4}@\s{0,4}|@\s{1,4}",
    )
    .expect("spelled at compiles")
});

/// A dot written out (`dot`, `point`, `[dot]`, `(.)`), or a plain `.` with
/// spaces only when one comes before it (`b . c`, never a sentence end).
/// Group 1 is set for a plain dot.
const SPELLED_DOT: &str = r"\s{0,4}[\[({<]\s{0,2}(?:dot|point|\.)\s{0,2}[\])}>]\s{0,4}|\s{1,4}(?:dot|point)\s{1,4}|(\s{1,4}\.\s{0,4}|\.)";
static DOT_AFTER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"(?i)\A(?:{SPELLED_DOT})")).expect("dot compiles"));
static DOT_BEFORE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"(?i)(?:{SPELLED_DOT})\z")).expect("dot compiles"));

/// Bytes one dot may span, bytes a local part may reach back from its `at`, and
/// most domain labels: bounded windows keep every cue's work constant.
const DOT_BYTES: usize = 24;
const LOCAL_BYTES: usize = 400;
const MAX_LABELS: usize = 32;

/// Words before a bare `at` that make it prose (`meet me at home dot thanks`).
const PROSE_LOCALS: &str = "me us him her them you it is are was were be look looked meet \
    arrive arrived stay stayed work worked live lived here there";
/// First labels after a bare `at` that make it prose (`look at the dot com era`).
const PROSE_LABELS: &str = "the a an this that these those it its his her their our your \
    some any each every one no which what whose least most all first last once";

/// Finds an e-mail address written out to dodge a scraper (K-PII-TRACE-GAPS-2):
/// `jane dot doe at example dot org`, `jane [at] example [dot] org`, `jean
/// arobase exemple point fr`. The local part is every word joined to the cue
/// by dots; the domain runs to its last alphabetic TLD. A bare `at` also needs a
/// written-out dot in the domain and a first label that is no prose word.
#[derive(Clone, Copy, Debug, Default)]
pub struct SpelledEmailRecognizer;

impl Recognizer for SpelledEmailRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Email]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        SPELLED_AT_RE
            .captures_iter(text)
            .filter_map(|cue| {
                let (whole, bare) = (cue.get(0)?, cue.get(1).is_some());
                let start = spelled_local_start(text, whole.start())?;
                if bare && super::secrets::one_of(PROSE_LOCALS, &text[start..whole.start()]) {
                    return None;
                }
                let end = spelled_domain_end(text, whole.end(), bare)?;
                Some(Span::new(EntityKind::Email, start, end, SCORE, self.name()))
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "email_spelled"
    }
}

/// The start of the local-part word ending at `end`, read no further back than
/// `floor`: letters, digits, `._%+-` and an apostrophe inside a word (`O'Neil`).
fn word_start(text: &str, floor: usize, end: usize) -> Option<usize> {
    let mut start = end;
    let mut chars = text[floor..end].char_indices().rev().peekable();
    while let Some((at, ch)) = chars.next() {
        let inner = matches!(ch, '\'' | '’')
            && chars
                .peek()
                .is_some_and(|&(_, before)| before.is_alphanumeric())
            && text[floor + at + ch.len_utf8()..].starts_with(char::is_alphanumeric);
        if !(ch.is_alphanumeric() || "._%+-".contains(ch) || inner) {
            break;
        }
        start = floor + at;
    }
    let lead = text[start..end].find(char::is_alphanumeric)?;
    Some(start + lead)
}

/// Where the local part before the cue at `cue` starts: every word joined to
/// it by dots, within [`LOCAL_BYTES`].
fn spelled_local_start(text: &str, cue: usize) -> Option<usize> {
    let floor = text.ceil_char_boundary(cue.saturating_sub(LOCAL_BYTES));
    let mut start = word_start(text, floor, cue)?;
    while start > floor {
        let from = text.ceil_char_boundary(start.saturating_sub(DOT_BYTES).max(floor));
        let Some(dot) = DOT_BEFORE_RE.find(&text[from..start]) else {
            break;
        };
        match word_start(text, floor, from + dot.start()) {
            Some(word) if word < start => start = word,
            _ => break,
        }
    }
    Some(start)
}

/// The end of the domain label at `at`: letters, digits and `-`, 1 to 63.
fn label_end(text: &str, at: usize) -> Option<usize> {
    let len: usize = text[at..]
        .chars()
        .take_while(|&ch| ch.is_alphanumeric() || ch == '-')
        .take(64)
        .map(char::len_utf8)
        .sum();
    let label = &text[at..at + len];
    (label.starts_with(char::is_alphanumeric) && label.chars().count() <= 63).then_some(at + len)
}

/// Where the domain after the cue ending at `at` ends: labels joined by dots,
/// up to the last one that is an alphabetic TLD after a dot.
fn spelled_domain_end(text: &str, at: usize, bare: bool) -> Option<usize> {
    let mut end = label_end(text, at)?;
    if bare && super::secrets::one_of(PROSE_LABELS, &text[at..end]) {
        return None;
    }
    let (mut found, mut spelled) = (None, false);
    for _ in 0..MAX_LABELS {
        let window = &text[end..text.floor_char_boundary(end + DOT_BYTES)];
        let Some(dot) = DOT_AFTER_RE.captures(window) else {
            break;
        };
        let label = end + dot.get(0)?.end();
        let Some(stop) = label_end(text, label) else {
            break;
        };
        spelled |= dot.get(1).is_none();
        let tld = &text[label..stop];
        if tld.chars().count() >= 2 && tld.chars().all(char::is_alphabetic) && (spelled || !bare) {
            found = Some(stop);
        }
        end = stop;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        EmailRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn accepts_valid_fake_addresses() {
        assert_eq!(hits("contact a@example.com now"), vec!["a@example.com"]);
        assert_eq!(
            hits("first.last+tag@sub.example.co.uk!"),
            vec!["first.last+tag@sub.example.co.uk"]
        );
    }

    #[test]
    fn masks_questionable_addresses_instead_of_leaking_them() {
        // Detection fails closed: an address-shaped match is masked even when
        // the strict structural check rejects its local part.
        assert_eq!(hits(".N@example.invalid"), vec![".N@example.invalid"]);
        assert_eq!(hits("a@example..com"), vec!["a@example..com"]);
        assert_eq!(hits("a@-example.com"), vec!["a@-example.com"]);
    }

    #[test]
    fn ignores_text_that_is_not_address_shaped() {
        assert!(hits("not an email").is_empty());
        assert!(hits("@example.com").is_empty());
        assert!(hits("a@@example.com").is_empty());
        assert!(hits("a@example").is_empty());
        assert!(hits("a@.com").is_empty());
    }

    #[test]
    fn questionable_scores_below_valid_but_still_masks() {
        let recognizer = EmailRecognizer::new();
        let valid = recognizer.analyze("a@example.com");
        let invalid = recognizer.analyze(".N@example.invalid");
        assert_eq!(valid.len(), 1);
        assert_eq!(invalid.len(), 1);
        assert_eq!(valid[0].score, SCORE);
        assert_eq!(invalid[0].score, QUESTIONABLE_SCORE);
        assert!(QUESTIONABLE_SCORE >= crate::Thresholds::new().get(EntityKind::Email));
    }

    #[test]
    fn accepts_unicode_local_parts_and_idn_domains() {
        assert_eq!(hits("müller@example.com"), vec!["müller@example.com"]);
        assert_eq!(
            hits("josé.dupont@example.invalid"),
            vec!["josé.dupont@example.invalid"]
        );
        assert_eq!(hits("jean@exémple.fr"), vec!["jean@exémple.fr"]);
        assert_eq!(hits("jean@example.рф"), vec!["jean@example.рф"]);
    }

    #[test]
    fn boundary_check_keeps_a_unicode_local_part_whole() {
        assert_eq!(hits("éa@example.com"), vec!["éa@example.com"]);
        assert_eq!(hits("café a@example.com"), vec!["a@example.com"]);
    }

    #[test]
    fn structural_check_vectors() {
        assert!(valid_email("a@example.com"));
        assert!(valid_email("müller@example.com"));
        assert!(valid_email("jean@example.рф"));
        assert!(!valid_email("a@b.c"));
        assert!(!valid_email("a b@example.com"));
        assert!(!valid_email("a@example.com."));
    }

    #[test]
    fn masks_every_adjacent_address_on_retry() {
        assert_eq!(
            hits("a@x.invalid.b@y.invalid"),
            vec!["a@x.invalid", "b@y.invalid"]
        );
        assert_eq!(
            hits("a@x.invalid-b@y.invalid"),
            vec!["a@x.invalid", "b@y.invalid"]
        );
        assert_eq!(
            hits("jean.dupont@example.invalid2026"),
            vec!["jean.dupont@example.invalid"]
        );
    }

    #[test]
    fn rejected_match_skips_the_whole_local_part_run() {
        // The trailing `¼` rejects the right boundary of the only match; the
        // retry must jump the whole local-part run instead of one character at
        // a time, so the scan stays linear (P2-4).
        let mut adversarial = "a.".repeat(20_000);
        adversarial.push_str("a@example.com¼");
        assert!(hits(&adversarial).is_empty());
        // A left-side rejection still lets the next address be found from its
        // own start.
        assert_eq!(
            hits("a@x.invalid.b@y.invalid"),
            vec!["a@x.invalid", "b@y.invalid"]
        );
    }

    #[test]
    fn fullwidth_email_is_folded_before_the_scan() {
        assert_eq!(
            hits("ｊｅａｎ＠ｅｘａｍｐｌｅ.ｃｏｍ"),
            vec!["ｊｅａｎ＠ｅｘａｍｐｌｅ.ｃｏｍ"]
        );
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = EmailRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::Email]);
        assert_eq!(recognizer.name(), "email");
        assert!(recognizer.verified());
    }
}
