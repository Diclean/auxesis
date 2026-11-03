//! TOK-DELEGATE: the token pairs a delegation carries between two sessions.
//!
//! In private mode a token resolves only in the session that minted it. One
//! [`Handoff`] per delegation run, in memory: the agent gets the caller's pairs
//! for the tokens in its task (no other), keeps every task token whole for its
//! model, and restores only those, only for an owner-account tool. The caller
//! adopts back only the tokens the agent's gate issued in that run. Anything
//! else, forged or from another run, stays opaque and refuses a tool call.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use aux_runtime::executor::TokenResolver;
use kernel_privacy::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};

use crate::skill_runtime::{session_tokens, SessionTokenStore};

/// Longest reference read as a token, as on the display side.
const MAX_TOKEN_BYTES: usize = 64;

tokio::task_local! {
    /// Set by the engine around a `delegate` call only.
    pub(crate) static CALLER: Caller;
}

/// What a delegated session takes from its caller for one task. No `Debug`:
/// it holds values.
#[derive(Clone, Default)]
pub struct Handoff {
    /// The caller's pairs for the task's tokens.
    pub(crate) pairs: Vec<(String, String)>,
    /// Every well-formed task token, known or not (the task is model text).
    pub(crate) kept: BTreeSet<String>,
    /// Tokens the agent's gate issued this run; `None` for an open caller.
    issued: Option<Arc<Mutex<BTreeSet<String>>>>,
    /// TOK-CONSISTENT-1: every pair the caller knows, so a value the agent
    /// reads keeps the caller's token; it resolves only once read this run.
    pub(crate) known: Vec<(String, String)>,
    /// Seal r2 P2b: the tokens of the agent's input this run (task, owner
    /// text, tool results); what its model wrote never counts.
    read: Arc<Mutex<BTreeSet<String>>>,
}

impl Handoff {
    /// Whether this handoff is from a private caller (else it carries nothing).
    pub fn is_private(&self) -> bool {
        self.issued.is_some()
    }

    /// Note the tokens of a text the agent's gate issued in this run.
    pub(crate) fn note_issued(&self, text: &str) {
        if let Some(issued) = &self.issued {
            let mut issued = kernel_core::sync::lock_recover(issued);
            issued.extend(references(text).into_iter().map(str::to_string));
        }
    }

    /// Note the tokens of a text the agent's provider read in this run.
    pub(crate) fn note_read(&self, text: &str) {
        let mut read = kernel_core::sync::lock_recover(&self.read);
        read.extend(references(text).into_iter().map(str::to_string));
    }

    /// The pairs the agent may resolve: the task's, and the known ones it read.
    pub(crate) fn resolvable(&self) -> Vec<(String, String)> {
        let read = kernel_core::sync::lock_recover(&self.read).clone();
        let known = self.known.iter().filter(|(token, _)| read.contains(token));
        self.pairs.iter().chain(known).cloned().collect()
    }

    /// The agent's pairs for the tokens of `answer` its gate issued this run:
    /// never one from its earlier runs or handed by another caller.
    pub fn returned_pairs(&self, agent_session: i64, answer: &str) -> Vec<(String, String)> {
        let Some(issued) = &self.issued else {
            return Vec::new();
        };
        let issued = kernel_core::sync::lock_recover(issued).clone();
        let store = session_tokens(agent_session);
        let mut pairs = pairs_in(&kernel_core::sync::lock_recover(&store), answer);
        pairs.retain(|(token, _)| issued.contains(token));
        pairs
    }
}

/// The session of the turn whose `delegate` call is running. No `Debug`.
#[derive(Clone)]
pub struct Caller {
    /// The calling session.
    pub session_id: i64,
    /// Whether the caller's gate tokenises.
    pub private: bool,
    pub(crate) tokens: Arc<Mutex<SessionTokenStore>>,
    /// The actual owner's words for this turn, never model text or persisted.
    pub(crate) owner_words: Option<String>,
}

impl Caller {
    /// The caller of the `delegate` call running on this task, if any.
    pub fn current() -> Option<Self> {
        CALLER.try_with(Clone::clone).ok()
    }

    /// The live caller's owner input, for local recipient checks only.
    pub fn owner_words(&self) -> Option<&str> {
        self.owner_words.as_deref()
    }

    /// What a delegated session takes for `task`: nothing from an open caller.
    pub fn handoff_for(&self, task: &str) -> Handoff {
        if !self.private {
            return Handoff::default();
        }
        let store = kernel_core::sync::lock_recover(&self.tokens);
        Handoff {
            issued: Some(Arc::default()),
            pairs: pairs_in(&store, task),
            kept: references(task)
                .into_iter()
                .filter(|token| well_formed(token))
                .map(str::to_string)
                .collect(),
            known: store.carried(),
            read: Arc::default(),
        }
    }

    /// Record pairs another session minted, so the caller's gate keeps their
    /// tokens and its display resolves them.
    pub fn adopt(&self, pairs: &[(String, String)]) {
        if self.private && !pairs.is_empty() {
            kernel_core::sync::lock_recover(&self.tokens).record(pairs);
        }
    }
}

fn pairs_in(store: &SessionTokenStore, text: &str) -> Vec<(String, String)> {
    let mut seen = BTreeSet::new();
    references(text)
        .into_iter()
        .filter(|token| seen.insert(*token))
        .filter_map(|token| store.resolve(token).map(|value| (token.to_string(), value)))
        .collect()
}

/// TOK-CONSISTENT-1 seal r2 P1: `issued`, what the gate made of the text as
/// written, with each name or address it `minted` that a carried token stands
/// for put back as that token (`own` keeps the choice for the next turns), then
/// each carried value it left in clear: the text to issue again and the tokens
/// to keep whole, or `None` when nothing changes. A value the detectors claimed
/// stays one masked unit; only its pseudonym changes.
pub(crate) fn carry(
    issued: &str,
    minted: &[(String, String)],
    own: &mut SessionTokenStore,
    handed: &[(String, String)],
    known: &[(String, String)],
) -> Option<(String, BTreeSet<String>)> {
    // Seal r3: each carried value is folded once (a lookup per token, never a
    // scan of every value), and an address keeps its accents: `info@côte.test`
    // is another mailbox than `info@cote.test`.
    let mut by_value: HashMap<String, &String> = HashMap::new();
    for (token, value) in handed.iter().chain(known) {
        by_value.entry(match_key(token, value)).or_insert(token);
    }
    let carried_tokens: HashSet<&String> = handed.iter().chain(known).map(|(t, _)| t).collect();
    let minted: HashSet<&str> = minted.iter().map(|(t, _)| t.as_str()).collect();
    let carries = |t: &String| carried_tokens.contains(t);
    let reused = replace_refs(issued, |token| {
        let alias = own.aliases.get(token).cloned();
        let carried = match alias.clone().filter(carries) {
            Some(alias) => alias,
            None => {
                // A token shown as itself keeps that; a new or aliased one
                // takes the carried token for its value, if this run has one.
                let fresh = alias.is_some() || minted.contains(token);
                let kinds = ["PERSON_", "ORGANIZATION_", "EMAIL_"];
                let named = kinds.iter().any(|kind| token.starts_with(kind));
                let value = own.resolve(token).filter(|_| fresh && named)?;
                let carried = *by_value.get(&match_key(token, &value))?;
                if carried.as_str() == token {
                    return None;
                }
                own.aliases.insert(token.to_string(), carried.clone());
                carried.clone()
            }
        };
        Some(format!("{PLACEHOLDER_OPEN}{carried}{PLACEHOLDER_CLOSE}"))
    });
    let named = retokenize(&reused, handed, known);
    (named != issued).then(|| {
        let keep = references(&named).into_iter().filter(|t| well_formed(t));
        let keep = keep.map(str::to_string).collect();
        // The gate reads it again: its escaped openers go back to one `⟦`.
        let doubled = format!("{PLACEHOLDER_OPEN}{PLACEHOLDER_OPEN}");
        (named.replace(&doubled, &PLACEHOLDER_OPEN.to_string()), keep)
    })
}

/// Replace each carried value in `text` with `⟦token⟧`. The match is
/// deterministic and needs no name model: case and accents are folded on both
/// sides, between word boundaries, never inside a token; the longest value wins
/// an overlap. A `handed` value (TOK-DELEGATE) matches with spaces folded off
/// too (`MARA QUELL`, `Mara  Quell`, `MaraQuell`, `Mara Quéll`: the mail
/// sanitizer may have joined two words); a `known` one keeps one space per run
/// (`Anna Bell` is not `Ann Abell`, seal r2 P2a). Linear in the text per value.
pub(crate) fn retokenize(
    text: &str,
    handed: &[(String, String)],
    known: &[(String, String)],
) -> String {
    if handed.is_empty() && known.is_empty() {
        return text.to_string();
    }
    let views = [fold(text, false), fold(text, true)];
    let spaced = handed.iter().map(|p| (p, false));
    let mut values: Vec<(&str, String, bool, String)> = spaced
        .chain(known.iter().map(|p| (p, true)))
        .map(|((token, value), spaced)| {
            let raw = value.trim().to_lowercase();
            (token.as_str(), fold(value.trim(), spaced).0, spaced, raw)
        })
        .filter(|(_, value, _, _)| value.chars().count() >= 2)
        .collect();
    values.sort_by_key(|(_, value, _, _)| std::cmp::Reverse(value.len()));
    // Disjoint taken ranges, start → (end, token): well-formed tokens already
    // there, then matches. Other bracketed text (`⟦Mara Quell⟧`) stays matchable.
    let mut taken: BTreeMap<usize, (usize, Option<&str>)> = references(text)
        .into_iter()
        .filter(|inner| well_formed(inner))
        .map(|inner| {
            let at = inner.as_ptr() as usize - text.as_ptr() as usize;
            let start = at - PLACEHOLDER_OPEN.len_utf8();
            (
                start,
                (at + inner.len() + PLACEHOLDER_CLOSE.len_utf8(), None),
            )
        })
        .collect();
    let word = |c: Option<char>| c.is_some_and(char::is_alphanumeric);
    for (token, value, spaced, raw) in &values {
        let (folded, origin) = &views[usize::from(*spaced)];
        for (at, _) in folded.match_indices(value.as_str()) {
            let (start, end) = (origin[at].0, origin[at + value.len() - 1].1);
            // Seal r3: an address matches its own accents only (case-blind).
            if token.starts_with("EMAIL_") && text[start..end].to_lowercase() != *raw {
                continue;
            }
            let clear = taken
                .range(..end)
                .next_back()
                .is_none_or(|(_, &(last, _))| last <= start);
            if clear
                && !word(text[..start].chars().next_back())
                && !word(text[end..].chars().next())
            {
                taken.insert(start, (end, Some(*token)));
            }
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (&start, &(end, token)) in &taken {
        if let Some(token) = token {
            out.push_str(&text[cursor..start]);
            out.push_str(&format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}"));
            cursor = end;
        }
    }
    out.push_str(&text[cursor..]);
    out
}

/// What two carried values must share to be one: an address lower-cased only
/// (accents name another mailbox), a name or organisation folded, one space per run.
fn match_key(token: &str, value: &str) -> String {
    if token.starts_with("EMAIL_") {
        value.trim().to_lowercase()
    } else {
        fold(value.trim(), true).0
    }
}

/// `text` lower-cased, accents and combining marks off, whitespace off or, when
/// `spaced`, one space per run; `origin[i]` is the source byte range of folded
/// byte `i`.
fn fold(text: &str, spaced: bool) -> (String, Vec<(usize, usize)>) {
    const ACCENTED: &str = "àáâãäåāăąçćčďèéêëēėęěìíîïīįıñńňòóôõöøōőřśšşťùúûüūůűųýÿžźżł";
    const PLAIN: &str = "aaaaaaaaacccdeeeeeeeeiiiiiiinnnoooooooorssstuuuuuuuuyyzzzl";
    let mut folded = String::with_capacity(text.len());
    let mut origin: Vec<(usize, usize)> = Vec::with_capacity(text.len());
    for (start, ch) in text.char_indices() {
        let end = start + ch.len_utf8();
        // Else a space joins nothing: the match spans it in the source anyway.
        if ch.is_whitespace() {
            if spaced && !folded.ends_with(' ') {
                folded.push(' ');
                origin.push((start, end));
            }
            continue;
        }
        // A combining mark belongs to the letter before it.
        if ('\u{300}'..='\u{36f}').contains(&ch) {
            if let Some(last) = origin.last_mut() {
                last.1 = end;
            }
            continue;
        }
        for c in ch.to_lowercase() {
            let c = ACCENTED
                .chars()
                .position(|a| a == c)
                .and_then(|i| PLAIN.chars().nth(i))
                .unwrap_or(c);
            folded.push(c);
            origin.resize(folded.len(), (start, end));
        }
    }
    (folded, origin)
}

/// TOK-CONSISTENT-1: each well-formed `⟦KIND_<hex>⟧` of `text` not in `keep`
/// (forged, or another conversation's) becomes `marker`, never a raw marker.
pub(crate) fn hide_unknown(text: &str, keep: &BTreeSet<String>, marker: &str) -> String {
    replace_refs(text, |token| {
        (!keep.contains(token)).then(|| marker.to_string())
    })
}

/// `text` with each well-formed reference `by` maps replaced, delimiters and all.
fn replace_refs(text: &str, mut by: impl FnMut(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for inner in references(text) {
        let Some(with) = well_formed(inner).then(|| by(inner)).flatten() else {
            continue;
        };
        let at = inner.as_ptr() as usize - text.as_ptr() as usize;
        out.push_str(&text[cursor..at - PLACEHOLDER_OPEN.len_utf8()]);
        out.push_str(&with);
        cursor = at + inner.len() + PLACEHOLDER_CLOSE.len_utf8();
    }
    out.push_str(&text[cursor..]);
    out
}

/// The kernel's token shape: `KIND_<12 upper hex>`, then an optional `_<n>`.
fn well_formed(token: &str) -> bool {
    let base = match token.rsplit_once('_') {
        Some((base, n)) if (1..12).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) => {
            base
        }
        _ => token,
    };
    base.rsplit_once('_').is_some_and(|(kind, hex)| {
        !kind.is_empty()
            && kind.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
            && hex.len() == 12
            && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))
    })
}

/// Each `KIND_<hex>` between `⟦` and `⟧` in `text`; a doubled `⟦⟦` is a
/// literal opener, as in the kernel's restore.
fn references(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(PLACEHOLDER_OPEN) {
        let after = &rest[at + PLACEHOLDER_OPEN.len_utf8()..];
        if let Some(literal) = after.strip_prefix(PLACEHOLDER_OPEN) {
            rest = literal;
            continue;
        }
        // Look for the closer only as far as a token can reach: linear, not quadratic.
        let window = after
            .char_indices()
            .map(|(i, _)| i)
            .find(|&i| i > MAX_TOKEN_BYTES + PLACEHOLDER_CLOSE.len_utf8())
            .unwrap_or(after.len());
        match after[..window].find(PLACEHOLDER_CLOSE) {
            Some(end)
                if end > 0
                    && end <= MAX_TOKEN_BYTES
                    && !after[..end].contains(PLACEHOLDER_OPEN) =>
            {
                found.push(&after[..end]);
                rest = &after[end + PLACEHOLDER_CLOSE.len_utf8()..];
            }
            _ => rest = after,
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_with_other_accents_is_another_mailbox() {
        // Seal r3 P2: `info@côte.test` never takes `info@cote.test`'s token.
        let known = [(
            "EMAIL_AAAAAAAAAAAA".to_string(),
            "info@cote.test".to_string(),
        )];
        assert_eq!(
            retokenize("info@côte.test and INFO@cote.test", &[], &known),
            "info@côte.test and ⟦EMAIL_AAAAAAAAAAAA⟧"
        );
        let mut own = SessionTokenStore::default();
        own.record(&[("EMAIL_BBBBBBBBBBBB".into(), "info@côte.test".into())]);
        let minted = [(
            "EMAIL_BBBBBBBBBBBB".to_string(),
            "info@côte.test".to_string(),
        )];
        assert_eq!(
            carry("to ⟦EMAIL_BBBBBBBBBBBB⟧", &minted, &mut own, &[], &known),
            None
        );
    }

    #[test]
    fn carrying_many_addresses_stays_linear() {
        // Seal r3 P2: 512 carried and 512 new addresses (14 s before, debug).
        let hex = |i: usize| format!("{i:012X}");
        let known: Vec<(String, String)> = (0..512)
            .map(|i| (format!("EMAIL_{}", hex(i)), format!("old{i}@fiction.test")))
            .collect();
        let minted: Vec<(String, String)> = (0..512)
            .map(|i| {
                (
                    format!("EMAIL_{}", hex(10_000 + i)),
                    format!("new{i}@fiction.test"),
                )
            })
            .collect();
        let mut own = SessionTokenStore::default();
        own.record(&minted);
        let issued: String = minted.iter().map(|(t, _)| format!("⟦{t}⟧ ")).collect();
        let started = std::time::Instant::now();
        assert_eq!(carry(&issued, &minted, &mut own, &[], &known), None);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn only_the_tokens_in_the_task_move_and_a_forged_one_carries_no_value() {
        let tokens = Arc::new(Mutex::new(SessionTokenStore::default()));
        kernel_core::sync::lock_recover(&tokens).record(&[
            ("PERSON_AAAAAAAAAAAA".into(), "Mara Quell".into()),
            ("EMAIL_BBBBBBBBBBBB".into(), "mara@quell.test".into()),
        ]);
        let caller = Caller {
            session_id: 1,
            private: true,
            tokens,
            owner_words: None,
        };
        let task = "mail from ⟦PERSON_AAAAAAAAAAAA⟧ and ⟦PERSON_AAAAAAAAAAAA⟧, \
                    not ⟦PERSON_0123456789AB_2⟧ nor ⟦⟦EMAIL_BBBBBBBBBBBB⟧ nor ⟦a b⟧";
        let handoff = caller.handoff_for(task);
        assert_eq!(
            handoff.pairs,
            [("PERSON_AAAAAAAAAAAA".to_string(), "Mara Quell".to_string())]
        );
        let kept: Vec<&str> = handoff.kept.iter().map(String::as_str).collect();
        assert_eq!(kept, ["PERSON_0123456789AB_2", "PERSON_AAAAAAAAAAAA"]);
        let open = Caller {
            session_id: 1,
            private: false,
            tokens: Arc::default(),
            owner_words: None,
        };
        let open = open.handoff_for(task);
        assert!(!open.is_private() && open.pairs.is_empty() && open.kept.is_empty());
    }

    /// Seal r2 P2b: a caller's token the agent's model only wrote (never read)
    /// fills no send: the snapshot a send fill and its card read refuses it.
    #[test]
    fn a_token_the_model_only_echoes_never_fills_a_send() {
        let tokens = Arc::new(Mutex::new(SessionTokenStore::default()));
        let echo = (
            "EMAIL_BBBBBBBBBBBB".to_string(),
            "hidden@fiction.test".to_string(),
        );
        kernel_core::sync::lock_recover(&tokens).record(&[echo]);
        let caller = Caller {
            session_id: 1,
            private: true,
            tokens,
            owner_words: None,
        };
        let handoff = caller.handoff_for("Write to the client.");
        handoff.note_issued("Sending to ⟦EMAIL_BBBBBBBBBBBB⟧.");
        let mut snapshot = SessionTokenStore::default();
        snapshot.record(&handoff.resolvable());
        let fill = serde_json::json!({ "to": "⟦EMAIL_BBBBBBBBBBBB⟧" });
        let filled = aux_runtime::executor::restore_value(&fill, &snapshot);
        assert!(filled.is_err(), "{filled:?}");
    }

    #[test]
    fn a_handed_value_is_put_back_in_any_case_spacing_or_accent() {
        let pairs = [
            ("PERSON_AAAAAAAAAAAA".to_string(), "Mara Quell".to_string()),
            (
                "EMAIL_BBBBBBBBBBBB".to_string(),
                "Mara@Quell.test".to_string(),
            ),
        ];
        let text =
            "MARA QUELL, Mara \u{a0} Quell, Mara Que\u{301}ll, MaraQuell, Mara Quéll <mara@quell.TEST> \
                    · Mara Quellen · ⟦PERSON_AAAAAAAAAAAA⟧";
        let out = retokenize(text, &pairs, &[]);
        let p = "⟦PERSON_AAAAAAAAAAAA⟧";
        let e = "⟦EMAIL_BBBBBBBBBBBB⟧";
        assert_eq!(
            out,
            format!("{p}, {p}, {p}, {p}, {p} <{e}> · Mara Quellen · {p}")
        );
    }

    #[test]
    fn a_handed_name_inside_brackets_that_are_not_a_token_is_still_hidden() {
        let pairs = [("PERSON_AAAAAAAAAAAA".to_string(), "Mara Quell".to_string())];
        let out = retokenize("the invoice for ⟦Mara Quell⟧ is attached.", &pairs, &[]);
        assert!(!out.contains("Mara Quell"), "{out}");
        assert!(out.contains("PERSON_AAAAAAAAAAAA"), "{out}");
    }

    #[test]
    fn many_unclosed_openers_are_scanned_in_linear_time() {
        let text = "⟦x".repeat(32_768);
        let started = std::time::Instant::now();
        assert!(references(&text).is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
