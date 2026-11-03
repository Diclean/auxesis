//! Stable per-session pseudonyms for detected values.
//!
//! Each surviving [`Span`] becomes a delimited `⟦KIND_<fingerprint>⟧`
//! placeholder. The token inside the delimiters is *not* a hash of the value:
//! it is the hex of the first bytes of an HMAC-SHA-256 (keyed from the vault)
//! over the kind and the normalised value, so two occurrences of one value get
//! the same token, a fresh session key gives different tokens, and a captured
//! token cannot be reversed by a dictionary attack. The caller receives the
//! `(token, original)` pairs and stores them in the vault, so
//! [`Anonymizer::restore`] returns the exact original bytes.
//!
//! A literal opener `⟦` (U+27E6) already in the input is written doubled
//! (`⟦⟦`) during [`Anonymizer::anonymize`]. Nothing else is rewritten:
//! backslashes, the closer `⟧` (U+27E7) and every other character pass through
//! byte-identical. A real token never starts with `⟦⟦`, so a user, a model or an
//! attacker cannot plant a token-shaped string that `restore` would mistake for
//! one of ours. `restore` reads left to right in a single pass: `⟦⟦` is one
//! literal `⟦`, and `⟦` followed by a token and `⟧` is a placeholder. Undelimited
//! token-like text is never touched.
//!
//! A value never appears in a token, in this type's `Debug` output, in
//! [`TokenMap`]'s `Debug` output, or in a log line.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::ops::Deref;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::normalize::NormalizedText;
use crate::recognizer::{masked_regions, span_is_well_formed, split_long_spans};
use crate::span::{EntityKind, Span};

type HmacSha256 = Hmac<Sha256>;

/// Opens a placeholder: `⟦` (U+27E6 LEFT WHITE SQUARE BRACKET).
pub const PLACEHOLDER_OPEN: char = '\u{27E6}';
/// Closes a placeholder: `⟧` (U+27E7 RIGHT WHITE SQUARE BRACKET).
pub const PLACEHOLDER_CLOSE: char = '\u{27E7}';

/// The marker [`UnknownPolicy::Redact`] writes for a token that is not in the
/// session's map. Matches the kernel's screen and send rule: a token that is
/// not in the map is never shown, it is replaced.
pub const UNKNOWN_REFERENCE: &str = "[unknown reference]";

/// What [`Anonymizer::restore`] does with a delimited token that is not in the
/// session's [`TokenMap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownPolicy {
    /// Leave the delimited token exactly as it appeared, so the caller can see
    /// what the model or the user invented. The report still names it.
    Keep,
    /// Replace the whole delimited token with [`UNKNOWN_REFERENCE`], matching
    /// the kernel's screen and send rule.
    Redact,
}

/// The text [`Anonymizer::restore`] produced and what it could not resolve.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// The restored text: known placeholders rehydrated, escapes reversed.
    pub text: String,
    /// The bare tokens found inside delimiters that are not in this session's
    /// map, in text order. A non-empty list means the caller must hold the send
    /// ("unknown or invented tokens").
    pub unknown: Vec<String>,
}

impl RestoreReport {
    /// Whether every delimited token resolved to a session value.
    pub fn is_clean(&self) -> bool {
        self.unknown.is_empty()
    }
}

/// The `(token, original)` pairs the caller stores in the vault.
///
/// The map keeps two views of the same masking run:
///
/// * `entries` is the *distinct* mapping, one `(token, first surface)` pair per
///   value, keyed by token (the token is an HMAC of the kind and the
///   *normalised* value, so `0612345678` and `06 12 34 56 78` share a token).
///   It is what the vault stores and what `Deref` exposes. Tokens here are
///   bare (`KIND_<fingerprint>`, no delimiters); the visible placeholder is the
///   delimited form written into masked text.
/// * `occurrences` is the *per-occurrence* list, `(token, exact surface)` in
///   masked-text order. A shared token can cover two different surface forms;
///   [`Anonymizer::restore`] walks this list to put each occurrence's exact
///   bytes back, so every masked occurrence round-trips byte for byte.
///
/// `Debug` prints only the tokens, so a stray log line can never leak a value.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TokenMap {
    entries: Vec<(String, String)>,
    occurrences: Vec<(String, String)>,
}

impl TokenMap {
    /// The number of distinct values.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no value has been seen yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The per-occurrence pairs in masked-text order. Crate-internal: the vault
    /// persists both views so [`Anonymizer::restore`] stays exact after a reload.
    pub(crate) fn occurrences(&self) -> &[(String, String)] {
        &self.occurrences
    }

    pub(crate) fn push_entry(&mut self, token: String, original: String) {
        self.entries.push((token, original));
    }

    pub(crate) fn push_occurrence(&mut self, token: String, original: String) {
        self.occurrences.push((token, original));
    }
}

impl Deref for TokenMap {
    type Target = [(String, String)];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

/// Zeroes every token and value when the map is dropped, so a stored value
/// does not outlive its map in the heap. Best effort: a `Vec` that grew
/// earlier may have left unscrubbed copies in freed memory.
impl Drop for TokenMap {
    fn drop(&mut self) {
        for (token, original) in self.entries.iter_mut().chain(self.occurrences.iter_mut()) {
            token.zeroize();
            original.zeroize();
        }
    }
}

impl fmt::Debug for TokenMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tokens: Vec<&str> = self
            .entries
            .iter()
            .map(|(token, _)| token.as_str())
            .collect();
        f.debug_struct("TokenMap")
            .field("entries", &self.entries.len())
            .field("occurrences", &self.occurrences.len())
            .field("tokens", &tokens)
            .finish()
    }
}

/// Maps spans to stable tokens using a per-session key.
pub struct Anonymizer {
    key: [u8; 32],
    table: HashMap<[u8; 32], String>,
    used_tokens: HashSet<String>,
}

impl Anonymizer {
    /// Build an anonymizer for one session with a 32-byte key from the vault.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            table: HashMap::new(),
            used_tokens: HashSet::new(),
        }
    }

    /// Replace every span in `text` with its delimited placeholder.
    ///
    /// Overlapping or adjacent spans of every kind are merged into one masked
    /// region first with [`crate::recognizer::masked_regions`], so no byte of any
    /// detection can survive in the clear and the masked text is exactly the
    /// union of the detected spans. Every region longer than
    /// [`crate::recognizer::MAX_SPAN_BYTES`] is split first, so one token never
    /// covers an unbounded region. Each placeholder is written as
    /// `⟦KIND_<fingerprint>⟧`; the text between placeholders is escaped so only
    /// our delimiters survive raw (see the module docs). Returns the masked
    /// text and the map of tokens; the map stores every occurrence's exact
    /// surface form, so [`Anonymizer::restore`] is exact even when one token
    /// covers several spellings of the same value.
    pub fn anonymize(&mut self, text: &str, spans: &[Span]) -> (String, TokenMap) {
        let well_formed: Vec<Span> = spans
            .iter()
            .copied()
            .filter(|span| span_is_well_formed(text, span))
            .collect();
        let ordered = split_long_spans(text, masked_regions(well_formed));

        let mut masked = String::with_capacity(text.len());
        let mut pairs = TokenMap::default();
        let mut cursor = 0usize;
        for span in ordered {
            if span.start < cursor {
                continue;
            }
            push_escaped(&mut masked, &text[cursor..span.start]);
            let surface = &text[span.start..span.end];
            let (token, is_new) = self.token_for(span.kind, surface);
            pairs.push_occurrence(token.clone(), surface.to_string());
            if is_new {
                pairs.push_entry(token.clone(), surface.to_string());
            }
            masked.push(PLACEHOLDER_OPEN);
            masked.push_str(&token);
            masked.push(PLACEHOLDER_CLOSE);
            cursor = span.end;
        }
        push_escaped(&mut masked, &text[cursor..]);
        (masked, pairs)
    }

    /// Replace every delimited placeholder in `text` with its original bytes.
    ///
    /// Parses the text left to right in a single pass. A doubled `⟦⟦` (a
    /// literal opener written by [`Anonymizer::anonymize`]) becomes one `⟦`;
    /// only the exact `⟦KIND_…⟧`
    /// delimiters are treated as placeholders, and only a token that is in
    /// `pairs` for this session is restored. An invented token, a token minted
    /// under another key, or any other text inside the delimiters is **not**
    /// restored: [`UnknownPolicy::Keep`] leaves it visible, while
    /// [`UnknownPolicy::Redact`] writes [`UNKNOWN_REFERENCE`]. Either way it is
    /// named in [`RestoreReport::unknown`] so the caller can hold the send.
    /// Undelimited token-like text is never touched.
    ///
    /// Per-occurrence surfaces are preserved: a token shared by two spellings
    /// restores each occurrence to its own exact surface form. This is an exact
    /// inverse of [`Anonymizer::anonymize`] for the map it returned.
    pub fn restore(text: &str, pairs: &TokenMap, unknown: UnknownPolicy) -> RestoreReport {
        let mut restored = String::with_capacity(text.len());
        let mut unresolved: Vec<String> = Vec::new();

        // Per-occurrence originals, consumed in masked order, so a shared token
        // restores each surface form byte for byte. `entries` is the fallback
        // when a known token appears more times than `anonymize` recorded.
        let mut queues: HashMap<&str, VecDeque<&str>> = HashMap::new();
        for (token, original) in &pairs.occurrences {
            if !token.is_empty() {
                queues
                    .entry(token.as_str())
                    .or_default()
                    .push_back(original.as_str());
            }
        }
        let entries: HashMap<&str, &str> = pairs
            .entries
            .iter()
            .map(|(token, original)| (token.as_str(), original.as_str()))
            .collect();

        let mut cursor = 0usize;
        let mut no_close = false;
        while cursor < text.len() {
            let ch = text[cursor..]
                .chars()
                .next()
                .expect("cursor is a char boundary");
            if ch == PLACEHOLDER_OPEN
                && text[cursor + PLACEHOLDER_OPEN.len_utf8()..].starts_with(PLACEHOLDER_OPEN)
            {
                // `⟦⟦` is the literal opener that `anonymize` wrote doubled.
                restored.push(PLACEHOLDER_OPEN);
                cursor += 2 * PLACEHOLDER_OPEN.len_utf8();
            } else if ch == PLACEHOLDER_OPEN {
                let inner_start = cursor + PLACEHOLDER_OPEN.len_utf8();
                let close = if no_close {
                    None
                } else {
                    text[inner_start..]
                        .find(PLACEHOLDER_CLOSE)
                        .map(|offset| inner_start + offset)
                };
                match close {
                    Some(inner_end) => {
                        let token = &text[inner_start..inner_end];
                        if token.is_empty() {
                            // `⟦⟧` is not one of our placeholders: keep it.
                            restored.push(PLACEHOLDER_OPEN);
                            restored.push(PLACEHOLDER_CLOSE);
                        } else if let Some(original) = queues
                            .get_mut(token)
                            .and_then(|queue| queue.pop_front())
                            .or_else(|| entries.get(token).copied())
                        {
                            restored.push_str(original);
                        } else {
                            unresolved.push(token.to_string());
                            match unknown {
                                UnknownPolicy::Keep => {
                                    restored.push(PLACEHOLDER_OPEN);
                                    restored.push_str(token);
                                    restored.push(PLACEHOLDER_CLOSE);
                                }
                                UnknownPolicy::Redact => restored.push_str(UNKNOWN_REFERENCE),
                            }
                        }
                        cursor = inner_end + PLACEHOLDER_CLOSE.len_utf8();
                    }
                    None => {
                        // No closing delimiter: the bracket is ordinary text.
                        // Once it is missing here, it is missing for every later
                        // open, so a run of `⟦` stays linear.
                        no_close = true;
                        restored.push(PLACEHOLDER_OPEN);
                        cursor = inner_start;
                    }
                }
            } else {
                restored.push(ch);
                cursor += ch.len_utf8();
            }
        }

        RestoreReport {
            text: restored,
            unknown: unresolved,
        }
    }

    /// The token for one value, assigning a new one on first sight.
    pub fn token_for(&mut self, kind: EntityKind, value: &str) -> (String, bool) {
        let digest = self.digest(kind, value);
        if let Some(existing) = self.table.get(&digest) {
            return (existing.clone(), false);
        }
        let token = self.make_token(kind, &digest);
        self.table.insert(digest, token.clone());
        self.used_tokens.insert(token.clone());
        (token, true)
    }

    /// The number of distinct values seen this session.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Whether no value has been seen yet.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// A keyed token: the kind plus the hex of `digest`, disambiguated if two
    /// values ever share the same short prefix. The used-token set makes the
    /// collision check O(1) instead of a scan of the table.
    fn make_token(&self, kind: EntityKind, digest: &[u8; 32]) -> String {
        let mut base = String::with_capacity(kind.as_str().len() + 13);
        base.push_str(kind.as_str());
        base.push('_');
        for byte in &digest[..6] {
            base.push_str(&format!("{byte:02X}"));
        }
        let mut attempt = 0u32;
        loop {
            let token = if attempt == 0 {
                base.clone()
            } else {
                format!("{base}_{attempt}")
            };
            if !self.used_tokens.contains(&token) {
                return token;
            }
            attempt += 1;
        }
    }

    fn digest(&self, kind: EntityKind, value: &str) -> [u8; 32] {
        let normalized = normalize_value(kind, value);
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts a key of any length");
        mac.update(kind.as_str().as_bytes());
        mac.update(b"\x1f");
        mac.update(normalized.as_bytes());
        // NORM-1: a spelling the scan folds (`𝐄𝐒91…`, `ЕS91…`, a hidden or
        // Unicode space) keys on its own bytes too, so it gets its own token and
        // restores to itself, never to another spelling of the value. A value
        // with nothing to fold (all ASCII text) keeps its key.
        if !NormalizedText::folded_views(value).is_empty() {
            mac.update(b"\x1e");
            mac.update(value.as_bytes());
        }
        let tag = mac.finalize().into_bytes();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&tag);
        digest
    }
}

impl fmt::Debug for Anonymizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Anonymizer")
            .field("key", &"<redacted>")
            .field("entries", &self.table.len())
            .finish()
    }
}

/// Put the real values back into an answer with a gate's minted pairs.
///
/// `minted` is the `(token, value)` list from
/// [`Gate::take_minted`](crate::safetext::Gate::take_minted). The parser is the
/// one [`Anonymizer::restore`] uses: a doubled `⟦⟦` becomes one literal `⟦`, a
/// known `⟦KIND_…⟧` becomes its value, and an unknown or malformed delimited
/// token follows `unknown` ([`UnknownPolicy::Keep`] leaves it visible,
/// [`UnknownPolicy::Redact`] writes [`UNKNOWN_REFERENCE`]). A marker with no
/// closing delimiter is ordinary text. Undelimited token-like text is never
/// touched.
///
/// This runs locally and returns text for the person who asked: never send the
/// result back to the model.
///
/// The gate reports one value per token, not every occurrence's spelling, so a
/// value the model wrote in a different spelling restores to the value the gate
/// reported. The pairs themselves are never printed.
#[must_use]
pub fn restore(answer: &str, minted: &[(String, String)], unknown: UnknownPolicy) -> String {
    // Reuse the one parser that already escapes openers and reads delimited
    // tokens left to right, so this helper cannot drift from `restore`'s
    // unknown-token and malformed-marker rules.
    let mut pairs = TokenMap::default();
    for (token, value) in minted {
        if !token.is_empty() {
            pairs.push_entry(token.clone(), value.clone());
        }
    }
    Anonymizer::restore(answer, &pairs, unknown).text
}

/// Append `clear` to `out`, doubling every literal opener.
///
/// This is the only rewrite [`Anonymizer::restore`] reverses: `⟦` becomes
/// `⟦⟦`. Every other character, backslashes included, is copied unchanged.
fn push_escaped(out: &mut String, clear: &str) {
    for ch in clear.chars() {
        out.push(ch);
        if ch == PLACEHOLDER_OPEN {
            out.push(PLACEHOLDER_OPEN);
        }
    }
}

/// Fold a value so visually identical values share a token, and distinct values
/// never do.
///
/// Every kind is NFKC-folded and trimmed first, so full-width forms match their
/// ASCII spelling. Then:
///
/// * a phone keeps its numeric characters and any `+`, so `+33 6 12 34 56 78`
///   and `+33612345678` match while `33612345678` stays apart;
/// * a card keeps its numeric characters only;
/// * the other identifier kinds (IBAN, NIR, passport…) keep every letter and
///   digit, folded to uppercase: a NIR's `2A` and `2B` department codes, and a
///   passport's letters, are part of the value;
/// * textual kinds (e-mails, names, places) keep every letter, accents and CJK
///   included, and are casefolded.
///
/// Dropping non-ASCII characters was the old collision: `ÉA1` became `A1`.
pub(crate) fn normalize_value(kind: EntityKind, value: &str) -> String {
    let folded: String = value.nfkc().collect();
    let trimmed = folded.trim();
    match kind {
        EntityKind::Phone => {
            let digits: String = trimmed
                .chars()
                .filter(|ch| ch.is_numeric() || *ch == '+')
                .collect();
            // A bare Chinese mobile is keyed in its E.164 form, so `13800138000`
            // and `+86 138 0013 8000` share one token.
            if is_bare_cn_mobile(&digits) {
                format!("+86{digits}")
            } else {
                digits
            }
        }
        EntityKind::CreditCard => trimmed.chars().filter(|ch| ch.is_numeric()).collect(),
        _ if kind.is_identifier() => trimmed
            .chars()
            .filter(|ch| ch.is_alphanumeric())
            .flat_map(char::to_uppercase)
            .collect(),
        // An address keeps its case folding, which its tests pin. Other text
        // keys on the exact spelling: `Le` and `le`, or `GROSS` and `Groß`, are
        // two tokens, and restore gives back each original byte for byte.
        EntityKind::Email => casefold(trimmed),
        _ => value.to_string(),
    }
}

/// Whether a phone value is eleven national digits starting `1[3-9]` with no
/// country code: the Chinese mobile shape the Standard phone rule masks bare.
fn is_bare_cn_mobile(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    bytes.len() == 11
        && bytes[0] == b'1'
        && (b'3'..=b'9').contains(&bytes[1])
        && bytes.iter().all(u8::is_ascii_digit)
}

/// Full case folding for textual values. Each character is lowercased on its
/// own, so no context rule applies (the final sigma folds like any other Σ, and
/// the Turkish dotless `ı` stays apart from `i`). The two letters whose fold is
/// more than one letter are spelled out, and NFKC runs again so a folded letter
/// keeps the composed form of its peers.
pub(crate) fn casefold(text: &str) -> String {
    let mut lowered = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            'ß' | 'ẞ' => lowered.push_str("ss"),
            'ς' => lowered.push('σ'),
            _ => lowered.extend(ch.to_lowercase()),
        }
    }
    lowered.nfkc().collect()
}

/// The kind a token was minted for, read from its `KIND_` prefix. The longest
/// matching kind name wins, so no kind name can shadow a longer one.
pub(crate) fn kind_of_token(token: &str) -> Option<EntityKind> {
    EntityKind::ALL
        .into_iter()
        .filter(|kind| {
            token
                .strip_prefix(kind.as_str())
                .is_some_and(|rest| rest.starts_with('_'))
        })
        .max_by_key(|kind| kind.as_str().len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(kind: EntityKind, start: usize, end: usize) -> Span {
        Span::new(kind, start, end, 1.0, "test")
    }

    fn restore_keep(text: &str, pairs: &TokenMap) -> String {
        Anonymizer::restore(text, pairs, UnknownPolicy::Keep).text
    }

    #[test]
    fn token_is_stable_within_a_session() {
        let mut anonymizer = Anonymizer::new([7u8; 32]);
        let text = "ecrivez a a@example.com puis a a@example.com";
        let first = text.find("a@example.com").unwrap();
        let second = text.rfind("a@example.com").unwrap();
        let spans = vec![
            span(EntityKind::Email, first, first + "a@example.com".len()),
            span(EntityKind::Email, second, second + "a@example.com".len()),
        ];
        let (masked, pairs) = anonymizer.anonymize(text, &spans);
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].0.starts_with("EMAIL_"));
        assert_eq!(pairs[0].1, "a@example.com");
        assert_eq!(masked.matches(&pairs[0].0).count(), 2);
        assert_eq!(masked.matches(PLACEHOLDER_OPEN).count(), 2);
        assert!(!masked.contains("a@example.com"));
    }

    #[test]
    fn two_keys_give_different_tokens() {
        let value = "a@example.com";
        let text = format!("mail {value}");
        let start = text.find(value).unwrap();
        let spans = vec![span(EntityKind::Email, start, start + value.len())];
        let mut one = Anonymizer::new([1u8; 32]);
        let mut two = Anonymizer::new([2u8; 32]);
        let (first_masked, first_pairs) = one.anonymize(&text, &spans);
        let (second_masked, second_pairs) = two.anonymize(&text, &spans);
        assert_eq!(first_pairs.len(), 1);
        assert_eq!(second_pairs.len(), 1);
        assert_ne!(first_pairs[0].0, second_pairs[0].0);
        assert_ne!(first_masked, second_masked);
        assert_ne!(
            one.digest(EntityKind::Email, value),
            two.digest(EntityKind::Email, value)
        );
    }

    #[test]
    fn distinct_values_get_distinct_tokens() {
        let mut anonymizer = Anonymizer::new([3u8; 32]);
        let (first, _) = anonymizer.token_for(EntityKind::Email, "a@example.com");
        let (second, _) = anonymizer.token_for(EntityKind::Email, "b@example.com");
        assert_ne!(first, second);
        assert_eq!(anonymizer.len(), 2);
    }

    #[test]
    fn kinds_are_part_of_the_digest_input() {
        let anonymizer = Anonymizer::new([3u8; 32]);
        assert_ne!(
            anonymizer.digest(EntityKind::Phone, "12345"),
            anonymizer.digest(EntityKind::FrSiren, "12345")
        );
    }

    #[test]
    fn identifier_normalisation_merges_separators_only() {
        assert_eq!(
            normalize_value(EntityKind::Phone, "+33 6 12 34 56 78"),
            normalize_value(EntityKind::Phone, "+33612345678")
        );
        assert_eq!(
            normalize_value(EntityKind::Iban, "fr76 3000 6000 0112 3456 7890 189"),
            normalize_value(EntityKind::Iban, "FR7630006000011234567890189")
        );
        // The leading + is part of the value, so these must not collide.
        assert_ne!(
            normalize_value(EntityKind::Phone, "+33612345678"),
            normalize_value(EntityKind::Phone, "33612345678")
        );
    }

    #[test]
    fn ascii_values_normalise_exactly_as_before() {
        // Golden stability: these inputs keep the same HMAC input as before the
        // Unicode fix, so their tokens do not move.
        assert_eq!(
            normalize_value(EntityKind::Email, "jean.dupont@example.test"),
            "jean.dupont@example.test"
        );
        assert_eq!(
            normalize_value(EntityKind::Phone, "+33 6 12 34 56 78"),
            "+33612345678"
        );
        assert_eq!(
            normalize_value(EntityKind::Iban, "fr76 3000 6000 0112 3456 7890 189"),
            "FR7630006000011234567890189"
        );
        assert_eq!(
            normalize_value(EntityKind::CreditCard, "4242 4242 4242 4242"),
            "4242424242424242"
        );
    }

    #[test]
    fn text_normalisation_keeps_every_letter_and_folds_case() {
        // An accented letter is part of the address: these must not collide.
        assert_ne!(
            normalize_value(EntityKind::Email, "José@example.test"),
            normalize_value(EntityKind::Email, "Jos@example.test")
        );
        assert_eq!(
            normalize_value(EntityKind::Email, "JOSÉ@Example.TEST"),
            normalize_value(EntityKind::Email, "josé@example.test")
        );
        // Full-width forms fold to ASCII under NFKC.
        assert_eq!(
            normalize_value(EntityKind::Email, "ｍａｒｉｅ@example.test"),
            normalize_value(EntityKind::Email, "marie@example.test")
        );
        // CJK letters are kept whole.
        assert_eq!(normalize_value(EntityKind::Person, "田中太郎"), "田中太郎");
        assert_ne!(
            normalize_value(EntityKind::Person, "田中太郎"),
            normalize_value(EntityKind::Person, "田中")
        );
        // Full case folding: ß folds to ss, and the final sigma to σ.
        assert_eq!(casefold("STRAßE"), casefold("Strasse"));
        // Text keys on its exact spelling: a folded spelling is another token.
        assert_ne!(
            normalize_value(EntityKind::Person, "STRAßE"),
            normalize_value(EntityKind::Person, "Strasse")
        );
        assert_eq!(casefold("ΟΔΟΣ"), casefold("οδος"));
        // The dotless ı is its own letter, not an i.
        assert_ne!(
            normalize_value(EntityKind::Person, "ısmail"),
            normalize_value(EntityKind::Person, "ismail")
        );
    }

    #[test]
    fn identifier_normalisation_keeps_letters_and_numerals_of_every_script() {
        // Non-ASCII letters used to vanish, so `ÉA1` and `A1` shared a key.
        assert_ne!(
            normalize_value(EntityKind::NationalId, "ÉA1"),
            normalize_value(EntityKind::NationalId, "A1")
        );
        // A Corsican NIR carries a letter in its department code.
        assert_ne!(
            normalize_value(EntityKind::FrNir, "1 85 2A 123 456 78"),
            normalize_value(EntityKind::FrNir, "1 85 2B 123 456 78")
        );
        // Full-width IBAN letters and digits fold like their ASCII spelling.
        assert_eq!(
            normalize_value(EntityKind::Iban, "ｆｒ76 3000"),
            normalize_value(EntityKind::Iban, "FR763000")
        );
        assert_eq!(
            normalize_value(EntityKind::Phone, "０６ １２ ３４ ５６ ７８"),
            normalize_value(EntityKind::Phone, "0612345678")
        );
        // Non-ASCII digits are kept rather than dropped to an empty key.
        assert_ne!(
            normalize_value(EntityKind::Phone, "٠٦"),
            normalize_value(EntityKind::Phone, "٧٠")
        );
        assert!(!normalize_value(EntityKind::Phone, "٠٦").is_empty());
    }

    #[test]
    fn shared_token_restores_each_surface_form() {
        let mut anonymizer = Anonymizer::new([0x55u8; 32]);
        let text = "tel 0612345678 puis 06 12 34 56 78 fin";
        let first = text.find("0612345678").unwrap();
        let second = text.find("06 12 34 56 78").unwrap();
        let spans = vec![
            span(EntityKind::Phone, first, first + "0612345678".len()),
            span(EntityKind::Phone, second, second + "06 12 34 56 78".len()),
        ];
        let (masked, pairs) = anonymizer.anonymize(text, &spans);
        // Same normalised value: one distinct entry, two occurrences.
        assert_eq!(pairs.len(), 1, "same normalised value must share a token");
        let token = pairs[0].0.clone();
        assert_eq!(masked.matches(&token).count(), 2);
        assert_eq!(restore_keep(&masked, &pairs), text);
    }

    #[test]
    fn tokens_key_on_the_exact_spelling_and_restore_it_byte_for_byte() {
        let mut anonymizer = Anonymizer::new([0x3Cu8; 32]);
        let text = "Le et le, GROSS et Groß.";
        let spans: Vec<Span> = ["Le", "le", "GROSS", "Groß"]
            .iter()
            .map(|word| {
                let start = text.find(word).expect("word in text");
                span(EntityKind::Person, start, start + word.len())
            })
            .collect();
        let (masked, pairs) = anonymizer.anonymize(text, &spans);
        assert_eq!(pairs.len(), 4, "each spelling keys its own token");
        assert_eq!(restore_keep(&masked, &pairs), text);
    }

    #[test]
    fn restore_round_trips_exact_text_including_plus() {
        let mut anonymizer = Anonymizer::new([4u8; 32]);
        let text = "tel +33 6 12 34 56 78 et mail a@b.co fin";
        let phone = text.find("+33").unwrap();
        let mail = text.find("a@b.co").unwrap();
        let spans = vec![
            span(EntityKind::Phone, phone, phone + "+33 6 12 34 56 78".len()),
            span(EntityKind::Email, mail, mail + "a@b.co".len()),
        ];
        let (masked, pairs) = anonymizer.anonymize(text, &spans);
        assert_eq!(pairs.len(), 2);
        assert!(pairs
            .iter()
            .any(|(_, original)| original == "+33 6 12 34 56 78"));
        assert_eq!(restore_keep(&masked, &pairs), text);
    }

    #[test]
    fn masked_text_keeps_surrounding_text_and_is_ordered() {
        let mut anonymizer = Anonymizer::new([4u8; 32]);
        let text = "tel 0612345678 et mail a@b.co fin";
        let phone_start = text.find("0612345678").unwrap();
        let mail_start = text.find("a@b.co").unwrap();
        let spans = vec![
            span(EntityKind::Email, mail_start, mail_start + 6),
            span(EntityKind::Phone, phone_start, phone_start + 10),
        ];
        let (masked, pairs) = anonymizer.anonymize(text, &spans);
        assert_eq!(pairs.len(), 2);
        assert!(pairs[0].0.starts_with("PHONE_"));
        assert!(pairs[1].0.starts_with("EMAIL_"));
        assert_eq!(
            masked,
            format!("tel ⟦{}⟧ et mail ⟦{}⟧ fin", pairs[0].0, pairs[1].0)
        );
    }

    #[test]
    fn literal_delimiters_are_escaped_and_restore_is_exact() {
        let mut anonymizer = Anonymizer::new([0x77u8; 32]);
        let text = "avant ⟦ et ⟧ puis 0612345678 fin";
        let start = text.find("0612345678").unwrap();
        let spans = vec![span(EntityKind::Phone, start, start + 10)];
        let (masked, pairs) = anonymizer.anonymize(text, &spans);
        // Only the literal opener is doubled; the closer is plain clear text.
        assert_eq!(masked.matches(PLACEHOLDER_OPEN).count(), 3);
        assert!(masked.starts_with("avant ⟦⟦ et ⟧ puis ⟦PHONE_"));
        assert_eq!(restore_keep(&masked, &pairs), text);
    }

    #[test]
    fn a_typed_placeholder_is_text_never_a_token() {
        let mut anonymizer = Anonymizer::new([0x7Du8; 32]);
        let mail = "a@example.com";
        let base = format!("mail {mail}");
        let start = base.find(mail).unwrap();
        let spans = [span(EntityKind::Email, start, start + mail.len())];
        let (_, first) = anonymizer.anonymize(&base, &spans);
        let token = first[0].0.clone();
        // A real token of this session, typed by the user after the real value.
        let text = format!("mail {mail} faux ⟦{token}⟧");
        let start = text.find(mail).unwrap();
        let spans = [span(EntityKind::Email, start, start + mail.len())];
        let (masked, pairs) = anonymizer.anonymize(&text, &spans);
        let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
        assert_eq!(report.text, text);
        assert!(report.is_clean(), "the typed look-alike must stay text");
    }

    #[test]
    fn backslashes_and_escape_lookalikes_round_trip() {
        let mut anonymizer = Anonymizer::new([0x78u8; 32]);
        let text = r"a \ b \\ c \u27E6 d 〚e〛 ⟧";
        let (masked, pairs) = anonymizer.anonymize(text, &[]);
        // Only a literal opener is rewritten: backslashes and look-alikes pass through.
        assert_eq!(masked, text);
        assert_eq!(restore_keep(&masked, &pairs), text);
    }

    #[test]
    fn unknown_delimited_token_is_reported_and_kept() {
        let mut anonymizer = Anonymizer::new([0x79u8; 32]);
        let (_, pairs) = anonymizer.anonymize("0612345678", &[span(EntityKind::Phone, 0, 10)]);
        let text = "masked ⟦PHONE_zzzzzz⟧ tail";
        let report = Anonymizer::restore(text, &pairs, UnknownPolicy::Keep);
        assert_eq!(report.unknown, vec!["PHONE_zzzzzz".to_string()]);
        assert_eq!(report.text, text);
        assert!(!report.is_clean());

        let report = Anonymizer::restore(text, &pairs, UnknownPolicy::Redact);
        assert_eq!(report.text, "masked [unknown reference] tail");
        assert_eq!(report.unknown, vec!["PHONE_zzzzzz".to_string()]);
    }

    #[test]
    fn cross_session_token_is_unknown() {
        let mut session = Anonymizer::new([0x7Au8; 32]);
        let (_, pairs) = session.anonymize("0612345678", &[span(EntityKind::Phone, 0, 10)]);
        let mut other = Anonymizer::new([0x7Bu8; 32]);
        let (forged, _) = other.token_for(EntityKind::Phone, "0612345678");
        let text = format!("⟦{forged}⟧");
        let report = Anonymizer::restore(&text, &pairs, UnknownPolicy::Keep);
        assert_eq!(report.unknown, vec![forged]);
    }

    #[test]
    fn undelimited_token_like_text_is_never_touched() {
        let mut anonymizer = Anonymizer::new([0x7Cu8; 32]);
        let (token, _) = anonymizer.token_for(EntityKind::Phone, "0612345678");
        let text = format!("{token} avant 0612345678 apres {token}");
        let start = text.find("0612345678").unwrap();
        let spans = vec![span(EntityKind::Phone, start, start + 10)];
        let (masked, pairs) = anonymizer.anonymize(&text, &spans);
        assert!(masked.contains(&format!("{token} avant")));
        let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
        assert_eq!(report.text, text);
        assert!(report.is_clean());
    }

    #[test]
    fn missing_close_delimiter_stays_literal() {
        let pairs = TokenMap::default();
        let text = "no close ⟦ here";
        let report = Anonymizer::restore(text, &pairs, UnknownPolicy::Keep);
        assert_eq!(report.text, text);
        assert!(report.is_clean());
    }

    #[test]
    fn debug_never_prints_a_value_or_key() {
        let mut anonymizer = Anonymizer::new([9u8; 32]);
        let (_, pairs) = anonymizer.anonymize(
            "secret@example.com",
            &[Span::new(EntityKind::Email, 0, 18, 1.0, "test")],
        );
        let rendered = format!("{anonymizer:?}");
        assert!(rendered.contains("redacted"));
        assert!(rendered.contains("entries: 1"));
        assert!(!rendered.contains("secret@example.com"));
        assert!(!rendered.contains("9, 9"));

        let map = format!("{pairs:?}");
        assert!(map.contains("tokens"));
        assert!(!map.contains("secret@example.com"));
        assert!(!format!("{pairs:?}").contains("secret"));
    }
}
