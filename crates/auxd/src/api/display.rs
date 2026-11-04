//! Screen rehydration: the local display side of the privacy kernel
//! (`docs/phase1.md` §2, the path rows).
//!
//! The cloud answers with tokens such as `⟦PERSON_1A2B3C4D5E6F⟧`. This module
//! turns a token back into the value it stands for, for text shown on the
//! owner's loopback surface only. Values never go back to the engine, the
//! provider, the store, memory, the audit or a log line:
//!
//! * [`SessionTokenSource`] is the per-session lookup. The engine reports the
//!   pairs each gate mints (`TurnEvents::session_tokens`), the API records them,
//!   and a token resolves only in the table of the session that minted it.
//!   [`MemorySessionTokens`] keeps the tables in process memory. The vault
//!   (slice 3) replaces it behind the same trait.
//! * [`Rehydrator`] is the grammar. A reference is the text between `⟦` and `⟧`,
//!   at most [`MAX_TOKEN_BYTES`] long; a doubled `⟦⟦` is one literal opener, as
//!   in `Anonymizer::restore`. An unknown or malformed reference shows the
//!   localised marker, never the raw text. A source that cannot answer keeps the
//!   token masked and sets the `unavailable` flag, which the frame carries as a
//!   banner.
//! * [`DisplayFeed`] streams text. It withholds only a trailing `⟦` that could
//!   still become a reference, so a token split across deltas is never shown
//!   half-raw. Its output equals [`Rehydrator::whole`] at every split point.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use kernel_core::Lang;
use kernel_privacy::{LinkGuard, PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};

use super::snapshot::MessageJson;

/// Longest reference (the bytes between `⟦` and `⟧`) read as a token. A real
/// token is a kind, `_`, 12 hex digits and an optional `_N`, far below this.
pub const MAX_TOKEN_BYTES: usize = 64;

/// What one session's table says about a reference.
#[derive(Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The value the token stands for in this session.
    Value(String),
    /// Not minted in this session: invented, malformed, or from another session.
    Unknown,
    /// The table cannot be read right now.
    Unavailable,
}

/// Redacted: a value never reaches a log line or a `{:?}`.
impl fmt::Debug for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(_) => f.write_str("Value(..)"),
            Self::Unknown => f.write_str("Unknown"),
            Self::Unavailable => f.write_str("Unavailable"),
        }
    }
}

/// The per-session lookup from a token to its value.
pub trait SessionTokenSource: Send + Sync {
    /// Remember the `(token, value)` pairs one gate minted for `session_id`.
    /// The first value seen for a token is the one kept.
    fn record(&self, session_id: i64, pairs: &[(String, String)]);

    /// Resolve `token` in `session_id`'s table only.
    fn resolve(&self, session_id: i64, token: &str) -> Resolution;

    /// Drop every pair `session_id` minted. Its references then resolve as unknown.
    /// No daemon path ends a session yet, so only the tests call this.
    #[allow(dead_code)]
    fn forget(&self, session_id: i64);
}

/// Most `(token, value)` pairs one session keeps. Past it the oldest pair goes,
/// and its token resolves as unknown: the owner sees the marker, never the token.
pub const MAX_PAIRS_PER_SESSION: usize = 4_096;

/// Most sessions the process keeps tables for. Past it the oldest session's
/// table goes first.
pub const MAX_SESSIONS: usize = 64;

/// One session's pairs. `order` holds the tokens oldest first, so eviction
/// drops the pair recorded first.
#[derive(Default)]
struct Table {
    values: BTreeMap<String, String>,
    order: VecDeque<String>,
}

impl Table {
    /// Keep the first value seen for `token`, evicting the oldest pair when full.
    fn insert(&mut self, token: &str, value: &str) {
        if self.values.contains_key(token) {
            return;
        }
        if self.values.len() >= MAX_PAIRS_PER_SESSION {
            if let Some(oldest) = self.order.pop_front() {
                self.values.remove(&oldest);
            }
        }
        self.values.insert(token.to_string(), value.to_string());
        self.order.push_back(token.to_string());
    }
}

/// Every session's table, and the order the tables were created in.
#[derive(Default)]
struct Sessions {
    tables: BTreeMap<i64, Table>,
    /// Session ids, oldest table first. Kept in step with `tables`.
    order: VecDeque<i64>,
}

impl Sessions {
    /// The table of `session_id`, created on first use. Creating one past
    /// [`MAX_SESSIONS`] drops the oldest table first.
    fn table_for(&mut self, session_id: i64) -> &mut Table {
        if !self.tables.contains_key(&session_id) {
            if self.tables.len() >= MAX_SESSIONS {
                if let Some(oldest) = self.order.pop_front() {
                    self.tables.remove(&oldest);
                }
            }
            self.order.push_back(session_id);
        }
        self.tables.entry(session_id).or_default()
    }
}

/// Per-session tables in process memory, the same lifetime as the session keys
/// they are derived from. Nothing is written to disk. Both levels are capped
/// ([`MAX_SESSIONS`], [`MAX_PAIRS_PER_SESSION`]), so the process holds a bounded
/// number of values however long it runs.
#[derive(Default)]
pub struct MemorySessionTokens {
    sessions: Mutex<Sessions>,
}

impl fmt::Debug for MemorySessionTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemorySessionTokens")
            .finish_non_exhaustive()
    }
}

impl SessionTokenSource for MemorySessionTokens {
    /// A poisoned table records nothing, and then resolves as unavailable:
    /// values are never guessed, and the screen keeps the tokens masked.
    fn record(&self, session_id: i64, pairs: &[(String, String)]) {
        if pairs.is_empty() {
            return;
        }
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        let table = sessions.table_for(session_id);
        for (token, value) in pairs {
            table.insert(token, value);
        }
    }

    fn resolve(&self, session_id: i64, token: &str) -> Resolution {
        let Ok(sessions) = self.sessions.lock() else {
            return Resolution::Unavailable;
        };
        match sessions
            .tables
            .get(&session_id)
            .and_then(|table| table.values.get(token))
        {
            Some(value) => Resolution::Value(value.clone()),
            None => Resolution::Unknown,
        }
    }

    /// Recovers a poisoned lock: an ended session's values must go even when an
    /// earlier panic poisoned the tables.
    fn forget(&self, session_id: i64) {
        let mut sessions = kernel_core::sync::lock_recover(&self.sessions);
        sessions.tables.remove(&session_id);
        sessions.order.retain(|&id| id != session_id);
    }
}

static LIVE_TOKENS: OnceLock<Arc<dyn SessionTokenSource>> = OnceLock::new();

/// The process's session tables, shared by every turn and by the snapshot routes.
pub fn live_tokens() -> Arc<dyn SessionTokenSource> {
    Arc::clone(LIVE_TOKENS.get_or_init(|| Arc::new(MemorySessionTokens::default())))
}

/// The text an unknown reference shows, in the owner's UI language.
pub fn unknown_marker(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "[name hidden]",
        Lang::Fr => "[nom masqué]",
    }
}

/// The owner's UI language (`[ui].language`) from the verified config, English
/// when the config cannot be read.
pub fn language_of(home: &Path) -> Lang {
    super::load_config_verified(home)
        .map(|config| config.ui.language)
        .unwrap_or_default()
}

/// Rehydrate the content of loopback message JSON in place. Each message reads
/// the references of its own session, so one response can span threads. The
/// sidebar preview is rebuilt from the rehydrated text through the full
/// detector: it shows no token and no hidden PII value.
pub fn rehydrate_messages(home: &Path, messages: &mut [MessageJson]) {
    let lang = language_of(home);
    let threads: std::collections::BTreeSet<i64> =
        messages.iter().map(|message| message.thread_id).collect();
    for thread_id in threads {
        load_stored_tokens(home, thread_id);
    }
    for message in messages {
        let rehydrator = Rehydrator::new(live_tokens(), message.thread_id, lang);
        message.content = rehydrator.whole(&message.content).text;
        message.preview = super::snapshot::message_preview(home, &message.content);
    }
}

/// Rehydrate one text of `thread_id` for the owner's loopback surface.
pub fn rehydrate_text(home: &Path, thread_id: i64, text: &str) -> String {
    load_stored_tokens(home, thread_id);
    Rehydrator::new(live_tokens(), thread_id, language_of(home))
        .whole(text)
        .text
}

fn note_link_redactions(count: usize) {
    if count > 0 {
        tracing::info!(kept_in_link = count, "link values kept hidden");
    }
}

/// Put `thread_id`'s stored token table (PRIVATE-TRANSCRIPT) into the live
/// tables, so a private thread shows its values after a restart. A store that
/// cannot be read adds nothing: its tokens then show the marker, never raw.
fn load_stored_tokens(home: &Path, thread_id: i64) {
    if let Ok(pairs) = super::snapshot::session_token_pairs(home, thread_id) {
        live_tokens().record(thread_id, &pairs);
    }
}

/// The text a rehydration produced, and whether a reference stayed masked
/// because its table was unavailable.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Rehydrated {
    /// The text with known prose references replaced and link values hidden.
    pub text: String,
    /// A token stayed masked because the session table could not be read.
    pub unavailable: bool,
}

/// Redacted: `text` is the owner's screen content and never prints.
impl fmt::Debug for Rehydrated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rehydrated")
            .field("unavailable", &self.unavailable)
            .finish_non_exhaustive()
    }
}

/// Rehydrates one session's text on the loopback surface.
pub struct Rehydrator {
    tokens: Arc<dyn SessionTokenSource>,
    session_id: i64,
    marker: &'static str,
}

/// How the scanner reads the opener at one position.
enum Step {
    /// `⟦⟦`: one literal opener.
    Escape,
    /// An opener that does not start a reference: ordinary text.
    Literal,
    /// A reference whose closer starts `len` bytes after the opener.
    Reference { len: usize },
    /// Not enough text yet to tell. Only possible before the end of the stream.
    Undecided,
}

/// One pass over a buffer.
struct Scanned {
    text: String,
    /// Bytes of the buffer the pass settled. The rest must be read again once
    /// more text arrives.
    settled: usize,
    unavailable: bool,
    kept_in_link: usize,
}

fn step(rest: &str, last: bool) -> Step {
    if rest.starts_with(PLACEHOLDER_OPEN) {
        return Step::Escape;
    }
    if rest.is_empty() {
        return if last { Step::Literal } else { Step::Undecided };
    }
    match rest.find([PLACEHOLDER_OPEN, PLACEHOLDER_CLOSE]) {
        Some(len) if len <= MAX_TOKEN_BYTES && rest[len..].starts_with(PLACEHOLDER_CLOSE) => {
            Step::Reference { len }
        }
        Some(_) => Step::Literal,
        None if last || rest.len() > MAX_TOKEN_BYTES => Step::Literal,
        None => Step::Undecided,
    }
}

impl Rehydrator {
    /// A rehydrator for `session_id` over `tokens`, marking unknown references in `lang`.
    pub fn new(tokens: Arc<dyn SessionTokenSource>, session_id: i64, lang: Lang) -> Self {
        Self {
            tokens,
            session_id,
            marker: unknown_marker(lang),
        }
    }

    /// The whole-buffer rehydration. A stream of the same text, split anywhere,
    /// concatenates to exactly this.
    pub fn whole(&self, text: &str) -> Rehydrated {
        let mut links = LinkGuard::default();
        let scanned = self.scan(text, true, &mut links);
        Rehydrated {
            text: scanned.text,
            unavailable: scanned.unavailable,
        }
    }

    fn scan(&self, buf: &str, last: bool, links: &mut LinkGuard) -> Scanned {
        let mut scanned = self.scan_at(buf, last, false, links);
        if last && scanned.settled == buf.len() {
            links.finish(&mut scanned.text);
        }
        scanned.kept_in_link = links.take_redactions();
        note_link_redactions(scanned.kept_in_link);
        scanned
    }

    /// One pass. A value holding a reference (a span took a kept token with it)
    /// is read once more, `nested`; deeper is the marker.
    fn scan_at(&self, buf: &str, last: bool, nested: bool, links: &mut LinkGuard) -> Scanned {
        let mut text = String::with_capacity(buf.len());
        let mut unavailable = false;
        let mut at = 0;
        while let Some(found) = buf[at..].find(PLACEHOLDER_OPEN) {
            let open = at + found;
            let plain = &buf[at..open];
            let rest = &buf[open + PLACEHOLDER_OPEN.len_utf8()..];
            let parsed = step(rest, last);
            if !last && matches!(&parsed, Step::Undecided) && plain.ends_with('<') {
                links.append_to(&mut text, &plain[..plain.len() - 1]);
                return Scanned {
                    text,
                    settled: open - 1,
                    unavailable,
                    kept_in_link: 0,
                };
            }
            links.append_to(&mut text, plain);
            match parsed {
                Step::Undecided => {
                    return Scanned {
                        text,
                        settled: open,
                        unavailable,
                        kept_in_link: 0,
                    }
                }
                Step::Escape => {
                    links.append_to(&mut text, "⟦");
                    at = open + 2 * PLACEHOLDER_OPEN.len_utf8();
                }
                Step::Literal => {
                    links.append_to(&mut text, "⟦");
                    at = open + PLACEHOLDER_OPEN.len_utf8();
                }
                Step::Reference { len } => {
                    let inner = &rest[..len];
                    at = open + PLACEHOLDER_OPEN.len_utf8() + len + PLACEHOLDER_CLOSE.len_utf8();
                    if inner.is_empty() {
                        // `⟦⟧` is not a reference: kept, as `Anonymizer::restore` keeps it.
                        links.append_to(&mut text, &buf[open..at]);
                        continue;
                    }
                    match self.tokens.resolve(self.session_id, inner) {
                        Resolution::Value(value) => {
                            match links.append_token_value(
                                &mut text,
                                inner,
                                &value,
                                &buf[at..],
                                last,
                            ) {
                                None => {
                                    return Scanned {
                                        text,
                                        settled: open,
                                        unavailable,
                                        kept_in_link: 0,
                                    };
                                }
                                Some(true) => {}
                                Some(false) if !nested => {
                                    let inner = self.scan_at(&value, true, true, links);
                                    unavailable |= inner.unavailable;
                                    text.push_str(&inner.text);
                                }
                                Some(false) => {
                                    links.append_value(&mut text, self.marker);
                                }
                            }
                        }
                        Resolution::Unknown => {
                            links.append_value(&mut text, self.marker);
                        }
                        Resolution::Unavailable => {
                            unavailable = true;
                            let raw = &buf[open..at];
                            if links.is_link_target() {
                                links.append_value(&mut text, "[hidden]");
                            } else {
                                links.append_to(&mut text, raw);
                            }
                        }
                    }
                }
            }
        }
        let tail = &buf[at..];
        if !last && tail.ends_with('<') {
            links.append_to(&mut text, &tail[..tail.len() - 1]);
            return Scanned {
                text,
                settled: buf.len() - 1,
                unavailable,
                kept_in_link: 0,
            };
        }
        links.append_to(&mut text, tail);
        Scanned {
            text,
            settled: buf.len(),
            unavailable,
            kept_in_link: 0,
        }
    }
}

/// Streaming rehydration. Feed it the text as it arrives; it releases what is
/// settled and holds the rest.
pub struct DisplayFeed {
    rehydrator: Rehydrator,
    /// The unsettled tail: an opener that may still become a reference, with
    /// at most [`MAX_TOKEN_BYTES`] bytes after it.
    pending: String,
    links: LinkGuard,
}

impl DisplayFeed {
    /// A feed over `rehydrator`, starting empty.
    pub fn new(rehydrator: Rehydrator) -> Self {
        Self {
            rehydrator,
            pending: String::new(),
            links: LinkGuard::default(),
        }
    }

    /// Append `text` and release everything that is settled.
    pub fn push(&mut self, text: &str) -> Rehydrated {
        self.pending.push_str(text);
        let scanned = self.rehydrator.scan(&self.pending, false, &mut self.links);
        self.pending.drain(..scanned.settled);
        Rehydrated {
            text: scanned.text,
            unavailable: scanned.unavailable,
        }
    }

    /// End of stream: release the rest. A trailing opener that never closed is
    /// shown as text.
    pub fn finish(&mut self) -> Rehydrated {
        let scanned = self.rehydrator.scan(&self.pending, true, &mut self.links);
        self.pending.clear();
        Rehydrated {
            text: scanned.text,
            unavailable: scanned.unavailable,
        }
    }
}

#[cfg(test)]
mod tests {

    /// A gate that tokenises: C9 is the one covered row private mode allows.
    fn tokenising_gate(key: [u8; 32]) -> kernel_privacy::safetext::Gate {
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::C9,
            kernel_core::privacy::PrivacyMode::Private,
            kernel_core::privacy::Destination::LocalDisplay,
        )
        .expect("C9 is covered in private mode");
        kernel_privacy::safetext::Gate::for_tests(
            &grant,
            key,
            aux_providers::test_gate::names_checked(),
        )
    }

    use super::*;

    const SESSION: i64 = 41;
    const PERSON: &str = "PERSON_1A2B3C4D5E6F";

    /// A table with `PERSON` → Élise Vautrin in `SESSION`.
    fn table() -> Arc<MemorySessionTokens> {
        let tokens = Arc::new(MemorySessionTokens::default());
        tokens.record(
            SESSION,
            &[(PERSON.to_string(), "Élise Vautrin".to_string())],
        );
        tokens
    }

    const LINK_PAIRS: [(&str, &str); 8] = [
        ("EMAIL_000000000001", "fixture.user@example.invalid"),
        ("PHONE_000000000002", "+10000000000"),
        ("IBAN_000000000003", "ZZ00TEST00000000000000"),
        ("CARD_000000000004", "0000000000000000"),
        ("ID_000000000005", "TEST-ID-0001"),
        ("HEALTH_000000000006", "fixture-condition-0001"),
        ("SECRET_000000000007", "test_secret_fixture_0001"),
        ("ADDRESS_000000000008", "1 Example Way, Fiction"),
    ];

    const LINK_TARGET_FORMATS: [&str; 8] = [
        "https://evil.invalid/p?d={token}|custom+v2://evil.invalid/{token}|www.evil.invalid/p?q={token}|https:{token}//evil.invalid/?q={token}",
        "evil.invalid/p?d={token}|//evil.invalid/p?d={token}|<evil.invalid/p?d={token}>",
        "[x][1]\n[1]: https://evil.invalid/p?d={token}|[x][1]\n[1]: /path?p={token}",
        "mailto:{token}|tel:{token}|data:text/plain,{token}|[report](https://evil.invalid/{token})|[x](https://evil.invalid/a\\)b?q={token})",
        "![x](https://evil.invalid/p?d={token})|<a href=\"https://evil.invalid/?q={token}\">report</a>|<a href=\"https://evil.invalid/?x=1>2&q={token}\">report</a>",
        "<img src='https://evil.invalid/i?q={token}'>|<https://evil.invalid/?q={token}>|HTTPS://evil.invalid/?q={token}",
        "hxxp://evil.invalid/?q={token}|https://evil.invalid/?q=\n{token}|https：//evil.invalid/?q={token}|https:\n//evil.invalid/?q={token}",
        "https:/evil.invalid/p?d={token}|https\u{200B}://evil.invalid/p?d={token}",
    ];

    fn link_table() -> Arc<MemorySessionTokens> {
        let tokens = Arc::new(MemorySessionTokens::default());
        let pairs = LINK_PAIRS.map(|(token, value)| (token.into(), value.into()));
        tokens.record(SESSION, &pairs);
        tokens
    }

    fn token(token: &str) -> String {
        format!("⟦{token}⟧")
    }

    fn en(tokens: Arc<dyn SessionTokenSource>) -> Rehydrator {
        Rehydrator::new(tokens, SESSION, Lang::En)
    }

    /// A source that cannot be read, as a vault that is down.
    struct Down;

    impl SessionTokenSource for Down {
        fn record(&self, _session_id: i64, _pairs: &[(String, String)]) {}

        fn forget(&self, _session_id: i64) {}

        fn resolve(&self, _session_id: i64, _token: &str) -> Resolution {
            Resolution::Unavailable
        }
    }

    /// Stream `text` cut at `cuts` and return what the screen shows.
    fn streamed(rehydrator: Rehydrator, text: &str, cuts: &[usize]) -> String {
        let mut feed = DisplayFeed::new(rehydrator);
        let mut shown = String::new();
        let mut from = 0;
        let end = text.len();
        for &cut in cuts.iter().chain(std::iter::once(&end)) {
            shown.push_str(&feed.push(&text[from..cut]).text);
            from = cut;
        }
        shown.push_str(&feed.finish().text);
        shown
    }

    #[test]
    fn known_references_show_their_value_and_unknown_ones_the_marker() {
        let text = format!("Bonjour ⟦{PERSON}⟧, ⟦PERSON_FFFFFFFFFFFF⟧.");
        let shown = en(table()).whole(&text);
        assert_eq!(shown.text, "Bonjour Élise Vautrin, [name hidden].");
        assert!(!shown.unavailable);

        let fr = Rehydrator::new(table(), SESSION, Lang::Fr).whole(&text);
        assert_eq!(fr.text, "Bonjour Élise Vautrin, [nom masqué].");
    }

    #[test]
    fn strict_superset_preserves_the_previous_link_corpus() {
        let rehydrator = en(link_table());

        for (kind, value) in LINK_PAIRS {
            let token = token(kind);
            for format in LINK_TARGET_FORMATS
                .into_iter()
                .flat_map(|group| group.split('|'))
            {
                let input = format.replace("{token}", &token);
                let shown = rehydrator.whole(&input);
                assert_eq!(shown.text, input.replace(&token, "[hidden]"), "{input:?}");
            }
            assert_eq!(
                rehydrator
                    .whole(&format!("Contact ⟦{kind}⟧ when ready."))
                    .text,
                format!("Contact {value} when ready.")
            );
        }

        let tokens = Arc::new(MemorySessionTokens::default());
        tokens.record(
            SESSION,
            &[(
                "URL_000000000009".into(),
                "https://evil.invalid/?d=fixture.user@example.invalid".into(),
            )],
        );
        let shown = en(tokens).scan("⟦URL_000000000009⟧", true, &mut LinkGuard::default());
        assert_eq!((shown.text.as_str(), shown.kept_in_link), ("[hidden]", 1));
        assert_eq!(
            rehydrator
                .whole("https://evil.invalid/?x=⟦UNKNOWN_FFFFFFFFFFFF⟧&q=⟦EMAIL_000000000001⟧")
                .text,
            "https://evil.invalid/?x=[hidden]&q=[hidden]"
        );
        let encoded = "https://evil.invalid/?q=%3Cemail_1%3E";
        assert_eq!(rehydrator.whole(encoded).text, encoded);
    }

    #[test]
    fn html_srcset_candidates_and_style_urls_stay_hidden() {
        let formats = [
            "<img srcset=\"https://x.invalid/1?q={token} 1x, https://y.invalid/2?q={token} 2x\">",
            "<source srcset='https://x.invalid/1?q={token} 1x, https://y.invalid/2?q={token} 2x'>",
            "<img srcset=https://x.invalid/1?q={token},https://y.invalid/2?q={token}>",
            "<div style=\"background:url(https://x.invalid/?q={token})\">",
            "<div style='background:url(https://x.invalid/?q={token})'>",
            "<div style=background:url(https://x.invalid/?q={token})>",
        ];
        let rehydrator = en(link_table());

        for (kind, _) in LINK_PAIRS {
            let token = token(kind);
            for format in formats {
                let input = format.replace("{token}", &token);
                let expected = input.replace(&token, "[hidden]");
                let scanned = rehydrator.scan(&input, true, &mut LinkGuard::default());
                assert_eq!(scanned.text, expected, "{input:?}");
                assert_eq!(
                    scanned.kept_in_link,
                    input.match_indices(&token).count(),
                    "{input:?}"
                );
            }
        }
    }

    #[test]
    fn every_token_class_stays_hidden_in_bare_host_labels() {
        let templates = [
            "{token}.evil.invalid/path",
            "customer.{token}.evil.invalid/path",
            "pre{token}post.evil.invalid/path",
        ];
        let rehydrator = en(link_table());
        let input = "⟦CARD_000000000004⟧.evil.invalid/path";
        let cuts = input
            .char_indices()
            .map(|(at, _)| at)
            .skip(1)
            .collect::<Vec<_>>();
        assert_eq!(
            streamed(en(link_table()), input, &cuts),
            "[hidden].evil.invalid/path"
        );

        for (kind, _) in LINK_PAIRS {
            let token = token(kind);
            for template in templates {
                let input = template.replace("{token}", &token);
                assert_eq!(
                    rehydrator.whole(&input).text,
                    input.replace(&token, "[hidden]"),
                    "{input:?}"
                );
            }
        }
    }

    #[test]
    fn any_html_attribute_with_a_url_shape_keeps_tokens_hidden() {
        let formats = [
            "<form action=\"https://evil.invalid/?d={token}\">go</form>",
            "<button formaction='custom+v2://evil.invalid/{token}'>go</button>",
            "<video poster=//evil.invalid/i?q={token}>",
            "<object data=\"https://evil.invalid/?d={token}\"></object>",
            "<img background='evil.invalid/i?q={token}'>",
            "<iframe srcdoc=\"https://evil.invalid/?d={token}\"></iframe>",
            "<div title=\"{token} then https://evil.invalid/?d=1\"></div>",
            "<div data=\"{token} custom+v2:payload\"></div>",
            "<img style src=\"https://evil.invalid/?q={token}\">",
            "<a href =\"https://evil.invalid/?q={token}\">report</a>",
        ];
        let rehydrator = en(link_table());
        for (kind, _) in LINK_PAIRS {
            let token = token(kind);
            for format in formats {
                let input = format.replace("{token}", &token);
                assert_eq!(
                    rehydrator.whole(&input).text,
                    input.replace(&token, "[hidden]"),
                    "{input:?}"
                );
            }
        }

        let input = "<div title=\"⟦EMAIL_000000000001⟧ then https://evil.invalid/\">";
        let cuts = input
            .char_indices()
            .map(|(at, _)| at)
            .skip(1)
            .collect::<Vec<_>>();
        assert_eq!(
            streamed(en(link_table()), input, &cuts),
            "<div title=\"[hidden] then https://evil.invalid/\">"
        );
    }

    #[test]
    fn encoded_url_punctuation_in_attributes_keeps_tokens_hidden() {
        let formats = [
            "<div title=\"{token} https&#58;&#x2F;&#47;evil&#46;invalid&#63;q&#61;1&#38;x&#35;frag&#64;local\">",
            "<div title=\"{token} https&colon;&sol;&sol;evil&period;invalid&quest;q&equals;1&amp;x&num;frag&commat;local\">",
            "<div data=\"https&colon;&sol;&sol;evil&period;invalid/?q={token}\">",
        ];
        let rehydrator = en(link_table());
        for (kind, _) in LINK_PAIRS {
            let token = token(kind);
            for format in formats {
                let input = format.replace("{token}", &token);
                assert_eq!(
                    rehydrator.whole(&input).text,
                    input.replace(&token, "[hidden]"),
                    "{input:?}"
                );
            }
        }
    }

    #[test]
    fn e_mail_autolink_keeps_its_visible_label_and_hides_its_destination() {
        let input = "Sender <⟦EMAIL_000000000001⟧>.";
        let shown = en(link_table()).scan(input, true, &mut LinkGuard::default());
        assert_eq!(
            shown.text,
            "Sender [fixture.user@example.invalid](mailto:[hidden])."
        );
        assert_eq!(shown.kept_in_link, 1);
        assert_eq!(
            en(link_table())
                .whole("Sender <⟦EMAIL_000000000001⟧ is listed")
                .text,
            "Sender <fixture.user@example.invalid is listed"
        );
        let cuts: Vec<_> = input.char_indices().map(|(at, _)| at).skip(1).collect();
        assert_eq!(streamed(en(link_table()), input, &cuts), shown.text);
    }

    #[test]
    fn bare_less_than_does_not_hide_following_prose() {
        let shown = en(link_table())
            .whole("The expression is 2 < word ⟦EMAIL_000000000001⟧ and remains prose.")
            .text;
        assert_eq!(
            shown,
            "The expression is 2 < word fixture.user@example.invalid and remains prose."
        );
    }

    #[test]
    fn unclosed_email_shaped_angle_does_not_hide_prose() {
        let shown = en(link_table())
            .whole("An unfinished <person@⟦HEALTH_000000000006⟧ remains prose.")
            .text;
        assert_eq!(
            shown,
            "An unfinished <person@fixture-condition-0001 remains prose."
        );
    }

    proptest::proptest! {
        #[test]
        fn random_prose_and_url_mixes_never_rehydrate_a_link_value(
            prose in "[a-zA-Z0-9 ,!?]{0,48}",
            path in "[a-zA-Z0-9/?=&._-]{0,48}",
            form in 0u8..7,
        ) {
            let email = token("EMAIL_000000000001");
            let target = match form {
                0 => format!("https://evil.invalid/{path}?q={email}"),
                1 => format!("evil.invalid/{path}?q={email}"),
                2 => format!("//evil.invalid/{path}?q={email}"),
                3 => format!("[x][1]\n[1]: https://evil.invalid/{path}?q={email}"),
                4 => format!("https:/evil.invalid/{path}?q={email}"),
                5 => format!("<https://evil.invalid/{path}?q={email}>"),
                _ => format!("[x](https://evil.invalid/{path}?q={email})"),
            };
            let input = format!("{prose}{target} | {prose}⟦EMAIL_000000000001⟧");
            let shown = en(link_table()).whole(&input).text;
            let (url, prose) = shown.split_once('|').unwrap();
            proptest::prop_assert!(!url.contains("fixture.user@example.invalid"));
            proptest::prop_assert!(prose.contains("fixture.user@example.invalid"));
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 20_000,
            ..proptest::test_runner::Config::default()
        })]
        #[test]
        fn link_guard_handles_twenty_thousand_lossy_unicode_inputs_without_panicking(
            bytes in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..128),
            class in 0usize..8,
            form in 0u8..3,
        ) {
            let rehydrator = en(link_table());
            let arbitrary = String::from_utf8_lossy(&bytes);
            let _ = rehydrator.whole(&arbitrary);

            let (kind, value) = LINK_PAIRS[class];
            let token = token(kind);
            let link = match form {
                0 => format!("{token}.evil.invalid/path"),
                1 => format!("<x title=\"{token} then https://evil.invalid/\">"),
                _ => format!("<x action=custom+v2://evil.invalid/{token}>"),
            };
            let shown = rehydrator.whole(&link).text;
            proptest::prop_assert!(!shown.contains(value), "{link:?} became {shown:?}");
        }
    }

    #[test]
    fn rehydration_stays_linear_on_10_and_100_kilobyte_mixes() {
        use std::time::{Duration, Instant};
        let phrase = "ordinary prose with 2 < 3 and no link target; ";
        let mut timings = Vec::new();
        for bytes in [10_000, 100_000] {
            let mut input = phrase.repeat(bytes / phrase.len());
            input.push_str("evil.invalid/p?q=⟦EMAIL_000000000001⟧");
            let start = Instant::now();
            let shown = en(link_table()).whole(&input).text;
            let elapsed = start.elapsed();
            assert!(shown.ends_with("evil.invalid/p?q=[hidden]"));
            eprintln!("link_guard {bytes} bytes: {} µs", elapsed.as_micros());
            timings.push(elapsed);
        }
        assert!(
            timings[1].as_nanos()
                <= timings[0].as_nanos() * 25 + Duration::from_millis(10).as_nanos()
        );
    }

    #[test]
    fn host_candidates_and_prose_stay_fast_at_100_kilobytes() {
        use std::time::{Duration, Instant};

        let rehydrator = en(link_table());
        let host_100k = "a.aa".repeat(25_000);
        let host_1m = "a.aa".repeat(250_000);
        let phrase = "ordinary prose with 2 < 3 and no link target; ";
        let mut prose_100k = phrase.repeat(100_000 / phrase.len());
        prose_100k.push_str(&phrase[..100_000 - prose_100k.len()]);
        let adversarial_shapes = [
            ("unmatched brackets", "["),
            ("angle probes", "<"),
            ("parentheses", "("),
            ("markdown target openers", "]("),
            ("nested markdown", "[nested]("),
            (
                "reference definitions",
                "\n[x][1]\n[1]: https://x.invalid/p\n",
            ),
            ("bare hosts", "x.invalid/p?q=v\n"),
            ("protocol-relative urls", "//x.invalid/p?q=v\n"),
            ("www urls", "www.x.invalid/p?q=v\n"),
            ("uppercase schemes", "HTTPS://x.invalid/p?q=v\n"),
            ("hxxp schemes", "hxxp://x.invalid/p?q=v\n"),
            ("single slash schemes", "https:/x.invalid/p?q=v\n"),
            ("split schemes", "https:\n//x.invalid/p?q=v\n"),
            (
                "format-character schemes",
                "https\u{200B}://x.invalid/p?q=v\n",
            ),
            ("full-width colon schemes", "https：//x.invalid/p?q=v\n"),
            (
                "srcset attributes",
                "<img srcset=\"https://x.invalid/a 1x, https://y.invalid/b 2x\">\n",
            ),
            (
                "CSS url attributes",
                "<div style=\"background:url(https://x.invalid/p)\">\n",
            ),
        ];

        let best_of_five = |input: &str| {
            let mut samples = Vec::new();
            for _ in 0..5 {
                let start = Instant::now();
                let shown = rehydrator.whole(input).text;
                samples.push(start.elapsed());
                assert_eq!(shown.len(), input.len());
            }
            samples.sort_unstable();
            samples[0]
        };

        let host_100k_time = best_of_five(&host_100k);
        let host_1m_time = best_of_five(&host_1m);
        let prose_time = best_of_five(&prose_100k);
        let mut worst_shape_time = Duration::ZERO;
        for (name, pattern) in adversarial_shapes {
            let small = pattern.repeat((10_000 / pattern.len()).max(1));
            let large = pattern.repeat((100_000 / pattern.len()).max(1));
            let small_time = best_of_five(&small);
            let large_time = best_of_five(&large);
            assert!(
                large_time <= small_time * 20 + Duration::from_millis(10),
                "{name} grew superlinearly: {small_time:?} -> {large_time:?}"
            );
            assert!(
                large_time <= Duration::from_millis(25),
                "{name} 100 kB: {large_time:?}"
            );
            worst_shape_time = worst_shape_time.max(large_time);
        }
        eprintln!(
            "link_guard host a.aa: 100 kB {} us, 1 MB {} us; prose 100 kB {} us; worst adversarial shape 100 kB {} us",
            host_100k_time.as_micros(),
            host_1m_time.as_micros(),
            prose_time.as_micros(),
            worst_shape_time.as_micros(),
        );
        assert!(
            host_100k_time <= Duration::from_millis(20),
            "a.aa 100 kB: {host_100k_time:?}"
        );
        assert!(
            host_1m_time <= Duration::from_millis(200),
            "a.aa 1 MB: {host_1m_time:?}"
        );
        assert!(
            prose_time <= Duration::from_millis(20),
            "prose 100 kB: {prose_time:?}"
        );
    }

    #[test]
    fn unterminated_attribute_token_scans_scale_to_twenty_thousand() {
        use std::time::{Duration, Instant};

        let rehydrator = en(link_table());
        let card = token("CARD_000000000004");
        let mut timings = Vec::new();
        for count in [500, 1_000, 2_000, 20_000] {
            let mut input = String::from("<div title=\"");
            for _ in 0..count {
                input.push_str(&card);
                input.push(' ');
            }
            let mut samples = Vec::new();
            for _ in 0..5 {
                let start = Instant::now();
                let shown = rehydrator.whole(&input).text;
                samples.push(start.elapsed());
                assert_eq!(shown.matches("[hidden]").count(), count);
                assert!(!shown.contains("0000000000000000"));
            }
            samples.sort_unstable();
            timings.push(samples[0]);
        }
        eprintln!(
            "unterminated attribute: 500 {} us, 1k {} us, 2k {} us, 20k {} us",
            timings[0].as_micros(),
            timings[1].as_micros(),
            timings[2].as_micros(),
            timings[3].as_micros(),
        );
        assert!(
            timings[3] < Duration::from_millis(100),
            "20k: {:?}",
            timings[3]
        );
    }

    #[test]
    fn comparison_prose_differential_restores_every_token_unchanged() {
        let marker = token("EMAIL_000000000001");
        let prose = [
            "2 < 3 then ",
            "x < y; ",
            "ordinary words ",
            "left > right; ",
            "value ",
        ];
        for seed in 0u64..2_000 {
            let mut state = seed.wrapping_add(1);
            let mut input = String::new();
            for _ in 0..10 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let choice = (state >> 32) as usize % (prose.len() + 1);
                if choice == prose.len() {
                    input.push_str(&marker);
                } else {
                    input.push_str(prose[choice]);
                }
            }
            let expected = input.replace(&marker, "fixture.user@example.invalid");
            assert_eq!(en(link_table()).whole(&input).text, expected, "seed {seed}");
        }
    }

    #[test]
    fn malformed_references_are_never_shown_raw() {
        let shown = en(table()).whole("a ⟦PERSON 3⟧ b ⟦⟧ c");
        assert_eq!(shown.text, "a [name hidden] b ⟦⟧ c");
    }

    #[test]
    fn a_doubled_opener_is_one_literal_and_never_a_reference() {
        let shown = en(table()).whole(&format!("⟦⟦{PERSON}⟧"));
        assert_eq!(shown.text, format!("⟦{PERSON}⟧"));
    }

    /// One level deep, then the marker.
    #[test]
    fn a_value_holding_a_reference_never_shows_it_raw() {
        let tokens = table();
        let (a, b) = ("PERSON_AAAAAAAAAAAA", "PERSON_BBBBBBBBBBBB");
        let pairs = [(a, format!("x ⟦{PERSON}⟧")), (b, format!("y ⟦{a}⟧"))];
        tokens.record(SESSION, &pairs.map(|(t, v)| (t.to_string(), v)));
        let shown = en(tokens).whole(&format!("⟦{a}⟧ ⟦{b}⟧"));
        assert_eq!(shown.text, "x Élise Vautrin y [name hidden]");
    }

    #[test]
    fn a_token_from_another_session_resolves_to_nothing() {
        let shown = Rehydrator::new(table(), SESSION + 1, Lang::En).whole(&format!("⟦{PERSON}⟧"));
        assert_eq!(shown.text, "[name hidden]");
    }

    #[test]
    fn an_unavailable_table_keeps_tokens_masked_and_flags_it() {
        let shown = en(Arc::new(Down)).whole(&format!("Bonjour ⟦{PERSON}⟧"));
        assert_eq!(shown.text, format!("Bonjour ⟦{PERSON}⟧"));
        assert!(shown.unavailable);
    }

    #[test]
    fn a_long_run_after_an_opener_is_text_and_is_not_held() {
        let long = format!("⟦{}", "x".repeat(MAX_TOKEN_BYTES + 8));
        let mut feed = DisplayFeed::new(en(table()));
        assert_eq!(feed.push(&long).text, long, "released at once");
        assert!(feed.finish().text.is_empty());
    }

    #[test]
    fn a_token_split_across_deltas_is_never_shown_half_raw() {
        let mut feed = DisplayFeed::new(en(table()));
        let first = feed.push("Bonjour ⟦PERS");
        assert_eq!(first.text, "Bonjour ", "the open token is held back");
        let second = feed.push("ON_1A2B3C4D5E6F⟧ merci");
        assert_eq!(second.text, "Élise Vautrin merci");
        assert!(feed.finish().text.is_empty());
    }

    #[test]
    fn a_trailing_opener_that_never_closed_is_shown_as_text_at_the_end() {
        let mut feed = DisplayFeed::new(en(table()));
        assert_eq!(feed.push("fin ⟦PERS").text, "fin ");
        assert_eq!(feed.finish().text, "⟦PERS");
    }

    #[test]
    fn streaming_matches_the_whole_buffer_at_every_split_point() {
        let text = format!(
            "A ⟦{PERSON}⟧ ⟦⟦{PERSON}⟧ ⟦PERSON_FFFFFFFFFFFF⟧ ⟦PERSON 3⟧ ⟦⟧ fin https://evil.invalid/?q=⟦EMAIL_000000000001⟧ and sender <⟦EMAIL_000000000001⟧>. ⟦{PERSON}⟧ ⟦PERS"
        );
        let whole = en(link_table()).whole(&text).text;
        for cut in text.char_indices().map(|(at, _)| at).skip(1) {
            assert_eq!(
                streamed(en(link_table()), &text, &[cut]),
                whole,
                "split at byte {cut}"
            );
        }
    }

    #[test]
    fn streaming_one_character_at_a_time_matches_the_whole_buffer() {
        let text = format!("⟦{PERSON}⟧ et ⟦PERSON_0000000000AA⟧ ⟦⟦x⟧ ⟦{PERSON}");
        let cuts: Vec<usize> = text.char_indices().map(|(at, _)| at).skip(1).collect();
        assert_eq!(
            streamed(en(table()), &text, &cuts),
            en(table()).whole(&text).text
        );
    }

    #[test]
    fn canary_value_reaches_the_screen_and_not_the_provider() {
        const CANARY: &str = "anne.dupont@example.org";
        let mut gate = tokenising_gate([7u8; 32]);
        let (masked, _) = gate.text(&format!("Écris à {CANARY} demain")).unwrap();
        let tokens = Arc::new(MemorySessionTokens::default());
        tokens.record(SESSION, &gate.take_minted());

        // The provider sees and answers with the masked text only.
        let token = masked
            .as_str()
            .split(PLACEHOLDER_OPEN)
            .nth(1)
            .and_then(|rest| rest.split(PLACEHOLDER_CLOSE).next())
            .expect("the email is masked");
        let reply = format!("Je réponds à ⟦{token}⟧.");
        assert!(!masked.as_str().contains(CANARY));
        assert!(!reply.contains(CANARY));

        // The owner's screen shows the value; the table never prints it.
        let screen = en(tokens.clone()).whole(&reply);
        assert_eq!(screen.text, format!("Je réponds à {CANARY}."));
        assert!(!format!("{tokens:?}").contains(CANARY));
    }

    /// The `index`th distinct pair: a well-formed token and its value.
    fn pair(index: usize) -> (String, String) {
        (format!("PERSON_{index:012X}"), format!("Personne {index}"))
    }

    #[test]
    fn forgetting_a_session_drops_its_values_and_no_other() {
        let tokens = table();
        let other = pair(2);
        tokens.record(SESSION + 1, std::slice::from_ref(&other));

        tokens.forget(SESSION);
        assert_eq!(tokens.resolve(SESSION, PERSON), Resolution::Unknown);
        assert_eq!(
            tokens.resolve(SESSION + 1, &other.0),
            Resolution::Value(other.1.clone())
        );
        assert!(!tokens.sessions.lock().unwrap().order.contains(&SESSION));
        assert_eq!(
            en(tokens.clone()).whole(&format!("⟦{PERSON}⟧")).text,
            "[name hidden]"
        );
    }

    #[test]
    fn a_session_past_its_pair_cap_evicts_the_oldest_pair_to_the_marker() {
        let tokens = Arc::new(MemorySessionTokens::default());
        let pairs: Vec<(String, String)> = (0..=MAX_PAIRS_PER_SESSION).map(pair).collect();
        tokens.record(SESSION, &pairs);

        let (oldest, newest) = (&pairs[0], &pairs[MAX_PAIRS_PER_SESSION]);
        assert_eq!(
            en(tokens.clone()).whole(&format!("⟦{}⟧", oldest.0)).text,
            "[name hidden]"
        );
        assert_eq!(
            tokens.resolve(SESSION, &newest.0),
            Resolution::Value(newest.1.clone())
        );
        let held = tokens.sessions.lock().unwrap().tables[&SESSION]
            .values
            .len();
        assert_eq!(held, MAX_PAIRS_PER_SESSION);
    }

    #[test]
    fn a_new_session_past_the_cap_evicts_the_oldest_session() {
        let tokens = Arc::new(MemorySessionTokens::default());
        for index in 0..=MAX_SESSIONS {
            tokens.record(index as i64, &[pair(index)]);
        }

        assert_eq!(tokens.resolve(0, &pair(0).0), Resolution::Unknown);
        assert_eq!(tokens.resolve(1, &pair(1).0), Resolution::Value(pair(1).1));
        let newest = MAX_SESSIONS;
        assert_eq!(
            tokens.resolve(newest as i64, &pair(newest).0),
            Resolution::Value(pair(newest).1)
        );
        assert_eq!(tokens.sessions.lock().unwrap().tables.len(), MAX_SESSIONS);
    }

    #[test]
    fn debug_output_never_prints_a_value() {
        let value = "Élise Vautrin";
        let resolved = Resolution::Value(value.to_string());
        assert!(!format!("{resolved:?}").contains(value));
        let shown = Rehydrated {
            text: value.to_string(),
            unavailable: true,
        };
        assert!(!format!("{shown:?}").contains(value));
    }
}
