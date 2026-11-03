//! API-key and token recogniser: each key is masked whole, prefix included.
//!
//! A key's prefix (`sk-`, `ghp_`, `AKIA`, `eyJ`) is part of the secret. A
//! detector that finds only the tail masks a fragment, leaves the prefix in
//! clear, and lets the tail match another rule: security-review B found an IBAN on the
//! tail of an `sk-proj-` key. So each shape below matches the whole key, and
//! the registry ranks a secret with the top label, so no IBAN, card or phone
//! shape relabels it.
//!
//! The shapes follow the issuers' documented formats. A minimum length keeps
//! `sk-learn` and other short words in clear. No word boundary is required: a
//! key glued to Han text, `_` or `-` is still a key. A key that a line break
//! wraps is joined across its continuation lines, bounded by
//! [`MAX_WRAP_BYTES`], so the scan stays linear. The
//! recogniser never logs a value.

use std::sync::LazyLock;

use regex::Regex;

use crate::contacts::fold::is_default_ignorable;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Score of a key. A key's shape is certain, so it sits above every floor.
pub const SCORE: f32 = 1.0;

/// The name echoed in [`Span::recognizer`].
const NAME: &str = "secrets";

/// Bytes a key may grow by joining its continuation lines. A provider key wraps
/// over a few lines; 8 KB is far past any real key, and it keeps the join bounded.
pub const MAX_WRAP_BYTES: usize = 8192;

/// The issuer key shapes: the prefix and the key alphabet after it, with the
/// shortest whole key (prefix included) each shape accepts.
const SHAPES: &[(&str, usize)] = &[
    // OpenAI and Anthropic keys: `sk-`, `sk-proj-`, `sk-ant-…`.
    // `sk-` must not follow a letter or digit (risk-…, task-…). The boundary is a
    // character outside the span, and the span is group 1.
    (r"(?:^|[^A-Za-z0-9])(sk-[A-Za-z0-9_\-]*)", 20),
    // Dropbox short-lived access tokens: `sl.`, same boundary rule as `sk-`.
    // `sl.u.` is the current layout (K-SKPROJ-GLUE).
    (r"(?:^|[^A-Za-z0-9])(sl\.(?:[a-z]\.)?[A-Za-z0-9_\-]*)", 24),
    // GitHub classic and OAuth tokens, and fine-grained personal tokens.
    (r"gh[pousr]_[A-Za-z0-9]*", 40),
    (r"github_pat_[A-Za-z0-9_]*", 33),
    // Slack bot, user, app and refresh tokens.
    (r"xox[abposr]-[A-Za-z0-9\-]*", 14),
    // Stripe secret, restricted and publishable keys, and webhook secrets.
    (r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]*", 16),
    (r"whsec_[A-Za-z0-9]*", 16),
    // Hugging Face and Groq tokens, GitLab personal tokens, Slack app-level
    // tokens, and the ya29. Google OAuth access token (after `Bearer `).
    (r"hf_[A-Za-z0-9]*", 33),
    (r"gsk_[A-Za-z0-9]*", 33),
    (r"glpat-[A-Za-z0-9_\-]*", 26),
    (r"xapp-[A-Za-z0-9\-]*", 14),
    (r"ya29\.[A-Za-z0-9_\-]*", 25),
    // K-GOOGLE-KEY: a ya29. token with more dots inside, such as the `ya29.c.`
    // service-account token, is read whole (the shape above stops at the dot).
    (r"ya29\.[A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]+)+", 25),
    // Package registries and hosting: npm, PyPI, SendGrid, DigitalOcean, Replicate,
    // Telegram bot tokens, Linear, Shopify, Shopify Storefront-free sbp_, Notion.
    (r"npm_[A-Za-z0-9]*", 40),
    (r"pypi-[A-Za-z0-9_\-]*", 50),
    (r"SG\.[A-Za-z0-9_\-.]*", 40),
    (r"dop_v1_[a-f0-9]*", 71),
    (r"r8_[A-Za-z0-9]*", 40),
    (r"[0-9]{8,10}:AA[A-Za-z0-9_\-]*", 44),
    (r"lin_api_[A-Za-z0-9]*", 40),
    (r"shpat_[a-f0-9]*", 38),
    (r"sbp_[a-f0-9]*", 44),
    (r"ntn_[A-Za-z0-9]*", 40),
    // Twilio API key SIDs (SK and 32 hex digits).
    (r"SK[0-9a-f]{32,}", 34),
    // age encryption secret keys.
    (r"AGE-SECRET-KEY-1[A-Z0-9]*", 40),
    // Google OAuth client secrets and refresh tokens, Meta access tokens, and Zoho
    // OAuth tokens (1000.x.y, one token).
    (r"GOCSPX-[A-Za-z0-9_\-]*", 28),
    (r"1//0[A-Za-z0-9_\-]*", 30),
    (r"EAA[A-Za-z0-9]*", 50),
    (r"1000\.[A-Za-z0-9]{8,}\.[A-Za-z0-9]{8,}", 20),
    // xAI, Perplexity, HashiCorp Vault, mesh VPN clients, Grafana, Sentry, Atlassian,
    // Supabase, Shopify, GitLab and Discord bot tokens.
    (r"xai-[A-Za-z0-9]*", 40),
    (r"pplx-[A-Za-z0-9]*", 40),
    (r"hvs\.[A-Za-z0-9_\-]*", 30),
    (r"tskey-[A-Za-z0-9_\-]*", 30),
    (r"glsa_[A-Za-z0-9_]*", 40),
    (r"sntrys_[A-Za-z0-9+/=_\-]*", 40),
    (r"ATATT3x[A-Za-z0-9_\-=]*", 40),
    (r"sb_secret_[A-Za-z0-9_\-]*", 30),
    (r"shpss_[a-f0-9]*", 37),
    (r"shpca_[a-f0-9]*", 38),
    (r"glptt-[a-f0-9]*", 46),
    // GitLab deploy tokens: `gldt-` plus 20 characters.
    (r"gldt-[A-Za-z0-9_\-]*", 25),
    // A Discord bot token: the first field is a user ID in base64, which starts
    // with M, N or O (IDs from 8 or 9 encode to OD or OT), then the timestamp and
    // the signature.
    (
        r"[MNO][A-Za-z0-9_\-]{23,28}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}",
        50,
    ),
    // AWS access key IDs (long-term and temporary).
    (r"(?:AKIA|ASIA)[0-9A-Z]*", 20),
    // Google API keys.
    (r"AIza[0-9A-Za-z_\-]*", 39),
    // JSON Web Tokens: a base64url header and payload, then an optional signature.
    (r"eyJ[A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]*)*", 12),
];

/// Finds API keys and tokens by their issuer shape.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretRecognizer;

impl SecretRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for SecretRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Secret]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let mut spans = Self::main_spans(text);
        for (start, end) in super::secret_link::link_scan(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        for (start, end) in lower_aws_keys(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        // SECRET-PROSE: only a span no older span holds is added.
        let mut held: Vec<(usize, usize)> = spans.iter().map(|s| (s.start, s.end)).collect();
        held.sort_unstable();
        let mut reach = 0;
        let reaches: Vec<usize> = held
            .iter()
            .map(|&(_, end)| {
                reach = reach.max(end);
                reach
            })
            .collect();
        for (start, end) in super::secret_prose::prose_scan(text) {
            let before = held.partition_point(|&(from, _)| from <= start);
            if before == 0 || reaches[before - 1] < end {
                spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
            }
        }
        // K-GOOGLE-KEY: an extra view, unioned with the scans above.
        for (start, end) in unescaped_keys(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        // K-SKPROJ-GLUE: an extra view, unioned with the scans above.
        for (start, end) in glued_keys(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        // SECRET-1: cookies, label lines, secret CSV columns, glued AWS ids.
        for (start, end) in super::secret_lines::lines_scan(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        to_line_ends(text, &mut spans);
        spans
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

impl SecretRecognizer {
    /// Every scan before K-SECRET-TAIL-4, unchanged: `link_scan` only adds to it.
    pub(crate) fn main_spans(text: &str) -> Vec<Span> {
        // Non-ASCII text is read through a view that drops zero-width characters
        // and maps fullwidth ASCII and dash variants; ASCII text is read as it is.
        let view = KeyView::for_text(text);
        let haystack = view.as_ref().map_or(text, |view| view.text.as_str());
        let original = |start: usize, end: usize| {
            view.as_ref()
                .map_or((start, end), |view| view.original(start, end))
        };
        let mut spans = Vec::new();
        for (shape, min_len) in SHAPES_RE.iter() {
            // The end of the last key this shape joined: a match inside it is
            // already covered, so its lines are not walked again.
            let mut consumed = 0;
            for captures in shape.captures_iter(haystack) {
                let Some(found) = captures.get(1).or_else(|| captures.get(0)) else {
                    continue;
                };
                if found.end() <= consumed {
                    continue;
                }
                let key = found.as_str();
                // Only the dotted ya29. shape matches a second dot after `ya29.`.
                let dotted = key.starts_with("eyJ")
                    || key.starts_with("SG.")
                    || key
                        .strip_prefix("ya29.")
                        .is_some_and(|rest| rest.contains('.'));
                let alphabet: fn(char) -> bool = if dotted {
                    is_dotted_key_char
                } else {
                    is_key_char
                };
                let mut end = join_wrapped(haystack, found.end(), alphabet);
                // `task-sk-<key>_build_id` presents a boundary-delimited `sk-`
                // after an identifier. Treat that ambiguous form like the
                // glued scan: validate the legacy key body and stop at it.
                if key.starts_with("sk-")
                    && found.start() >= 2
                    && haystack.as_bytes()[found.start() - 1] == b'-'
                    && haystack.as_bytes()[found.start() - 2].is_ascii_alphanumeric()
                {
                    let candidate = &haystack[found.start()..end];
                    if candidate.len() >= 51 && known_glued_format(&candidate[..51]) {
                        end = found.start() + 51;
                    }
                }
                consumed = end;
                if end - found.start() >= *min_len {
                    let (from, to) = original(found.start(), end);
                    spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
                }
            }
        }
        for captures in AWS_SECRET_RE.captures_iter(haystack) {
            if let Some(value) = captures.get(1) {
                // A wrapped value joins its continuation lines.
                let end = join_wrapped(haystack, value.end(), is_value_char);
                let (from, to) = original(value.start(), end);
                spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
            }
        }
        for value in secret_values(haystack) {
            let (from, to) = original(value.start, value.end);
            spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
        }
        // The DSN shape needs `://`, so a text without it skips the scan.
        if haystack.contains("://") {
            for captures in DSN_USERINFO_RE.captures_iter(haystack) {
                let (Some(user), Some(password)) = (captures.get(1), captures.get(2)) else {
                    continue;
                };
                let start = if user.is_empty() {
                    password.start()
                } else {
                    user.start()
                };
                let (from, to) = original(start, password.end());
                spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
            }
        }
        for captures in AUTHORIZATION_RE.captures_iter(haystack) {
            if let Some(value) = captures.get(1) {
                let (from, to) = original(value.start(), value.end());
                spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
            }
        }
        for block in PUTTY_KEY_RE
            .find_iter(haystack)
            .chain(HEADERLESS_PEM_RE.find_iter(haystack))
            .chain(PEM_BLOCK_RE.find_iter(haystack))
        {
            let (from, to) = original(block.start(), block.end());
            spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
        }
        spans
    }
}

/// K-GOOGLE-KEY: the keys written with markdown escapes (`AIza…\_…`, `ya29.c.…\-…`).
/// The key alphabet stops at the backslash, so the head before it is too short
/// and the whole key stayed clear. The text is read once more with each
/// backslash before `_` or `-` dropped; a key found there maps back to the text,
/// backslashes included. Only a key that holds a dropped backslash is returned:
/// every other key is the main scan's, read on the same bytes.
fn unescaped_keys(text: &str) -> Vec<(usize, usize)> {
    if !text.contains("\\_") && !text.contains("\\-") {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let mut view = String::with_capacity(text.len());
    // The view offsets where a backslash was dropped, ascending.
    let mut cuts = Vec::new();
    let mut from = 0;
    for (at, _) in text.match_indices('\\') {
        if matches!(bytes.get(at + 1), Some(b'_' | b'-')) {
            view.push_str(&text[from..at]);
            cuts.push(view.len());
            from = at + 1;
        }
    }
    view.push_str(&text[from..]);
    SecretRecognizer::main_spans(&view)
        .into_iter()
        .filter_map(|span| {
            let before_start = cuts.partition_point(|&cut| cut <= span.start);
            let before_end = cuts.partition_point(|&cut| cut < span.end);
            (before_end > before_start)
                .then_some((span.start + before_start, span.end + before_end))
        })
        .collect()
}

/// K-SKPROJ-GLUE: an `sk-` key (`sk-proj-`, `sk-ant-`) or an `sl.` token glued
/// after a letter or a digit (`notesk-proj-…`). The two shapes in [`SHAPES`] need
/// a character other than a letter or digit before the prefix. Here the
/// boundary is dropped: exact-length OpenAI bodies are accepted by length,
/// except when the entire run after `sk-` reads as identifier words. Longer
/// issuer formats retain the random-tail shape checks. The accepted span ends
/// at the key body, so a following identifier suffix stays clear. Keys after a
/// non-alphanumeric character are the main scan's; this view only adds.
static GLUED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:sk-|sl\.(?:[a-z]\.)?)[A-Za-z0-9_\-]*").expect("glued key compiles")
});

/// Key characters the long tails of `sk-proj-`, `sk-svcacct-`, `sk-admin-`,
/// `sk-ant-…` and `sl.` tokens need after their sub-prefix. Real tails run about
/// 95 to 200 characters. Such a tail also needs both cases and a digit, and a
/// change between lower case, upper case and digits for at least every
/// [`GLUED_LONG_TURN_EVERY`] characters (a random tail has one every 1.6):
/// slugs, words and repeated filler have far fewer.
const GLUED_MIN_LONG_TAIL: usize = 80;
const GLUED_LONG_TURN_EVERY: usize = 4;

/// Whether `run`, the whole run of key characters of a glued `sk-` or `sl.`
/// match (prefix included, ended by a non-key character or the end of the
/// text), is one of the issuers' exact formats:
///
/// * OpenAI legacy: `sk-` + exactly 48 `[A-Za-z0-9]`;
/// * OpenAI project: `sk-proj-` + exactly 48 or 64 `[A-Za-z0-9]` without the
///   optional marker;
/// * DeepSeek: `sk-` + exactly 32 lower-case hex;
/// * OpenRouter: `sk-or-v1-` + exactly 64 lower-case hex;
/// * any `sk-` tail of [`GLUED_MIN_TAIL`]+ key characters with the OpenAI
///   marker `T3BlbkFJ`;
/// * `sk-proj-`, `sk-svcacct-`, `sk-admin-`, `sk-ant-api0…`, `sk-ant-admin0…`,
///   Dropbox `sl.` and `sl.u.`: [`GLUED_MIN_LONG_TAIL`]+ key characters after
///   the sub-prefix that read as random (see [`GLUED_LONG_TURN_EVERY`]).
///
/// A random 32-hex or 48-character ID after `task-` or `disk-` is masked too:
/// an accepted over-mask, a key may not leak.
fn known_glued_format(run: &str) -> bool {
    let all =
        |tail: &str, n: usize, ok: fn(&u8) -> bool| tail.len() == n && tail.bytes().all(|b| ok(&b));
    let hex = |b: &u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    let has = |tail: &str, ok: fn(&u8) -> bool| tail.bytes().any(|b| ok(&b));
    let class = |b: &u8| match b {
        b'a'..=b'z' => 1,
        b'A'..=b'Z' => 2,
        b'0'..=b'9' => 3,
        _ => 0,
    };
    let long = |tail: &str| {
        let turns = tail
            .as_bytes()
            .windows(2)
            .filter(|w| class(&w[0]) * class(&w[1]) != 0 && class(&w[0]) != class(&w[1]))
            .count();
        tail.len() >= GLUED_MIN_LONG_TAIL
            && turns * GLUED_LONG_TURN_EVERY >= tail.len()
            && has(tail, u8::is_ascii_lowercase)
            && has(tail, u8::is_ascii_uppercase)
            && has(tail, u8::is_ascii_digit)
    };
    if let Some(rest) = run.strip_prefix("sl.") {
        let rest = match rest.as_bytes() {
            [b'a'..=b'z', b'.', ..] => &rest[2..],
            _ => rest,
        };
        return long(rest);
    }
    let Some(tail) = run.strip_prefix("sk-") else {
        return false;
    };
    all(tail, 48, u8::is_ascii_alphanumeric)
        || tail.strip_prefix("proj-").is_some_and(|rest| {
            all(rest, 48, u8::is_ascii_alphanumeric) || all(rest, 64, u8::is_ascii_alphanumeric)
        })
        || all(tail, 32, hex)
        || tail
            .strip_prefix("or-v1-")
            .is_some_and(|rest| all(rest, 64, hex))
        || (tail.len() >= GLUED_MIN_TAIL && tail.contains("T3BlbkFJ"))
        || ["proj-", "svcacct-", "admin-", "ant-api0", "ant-admin0"]
            .into_iter()
            .any(|sub| tail.strip_prefix(sub).is_some_and(long))
}

/// A whole glued run is exempt only when it reads as identifier words. Split
/// camelCase and explicit separators, then reject mixed-case/digit segments
/// before the inexpensive pronounceability check.
fn plainly_words(run: &str) -> bool {
    let Some(tail) = run.strip_prefix("sk-") else {
        return false;
    };
    let mut words = Vec::new();
    let mut start = 0;
    let b = tail.as_bytes();
    for i in 1..=b.len() {
        let separator = i < b.len() && matches!(b[i], b'_' | b'-' | b'.');
        let boundary = i == b.len()
            || separator
            || (i < b.len()
                && ((b[i].is_ascii_uppercase() && b[i - 1].is_ascii_lowercase())
                    || (b[i].is_ascii_digit() != b[i - 1].is_ascii_digit())));
        if boundary {
            if i > start {
                words.push(&tail[start..i]);
            }
            start = i + usize::from(separator);
        }
    }
    // A clear run must visibly read as a segmented identifier. A single
    // unsegmented word (including repeated-word filler) is never enough.
    let alpha_words = words
        .iter()
        .filter(|word| word.bytes().all(|b| b.is_ascii_alphabetic()))
        .count();
    alpha_words >= 3
        && words.iter().enumerate().all(|(index, word)| {
            let bytes = word.as_bytes();
            if bytes.iter().all(u8::is_ascii_digit) {
                // Keep the #231 identifiers with a trailing year clear, but
                // don't exempt short numeric suffixes or mixed tokens.
                return index + 1 == words.len() && bytes.len() == 4;
            }
            if !bytes.iter().all(u8::is_ascii_alphabetic) {
                return false;
            }
            if bytes.len() < 3 {
                // Preserve the pre-existing #231 camel-case examples, whose
                // two-letter function-word segments are part of longer clear
                // identifiers. The three substantial alphabetic segments
                // required above still prevent a short label from opening an
                // otherwise unsegmented key.
                return ["in", "of", "to", "by", "de", "du", "et", "la", "le", "on"]
                    .iter()
                    .any(|short| word.eq_ignore_ascii_case(short));
            }
            if bytes.first().is_some_and(u8::is_ascii_uppercase) {
                if !bytes[1..].iter().all(u8::is_ascii_lowercase) {
                    return false;
                }
            } else if !bytes.iter().all(u8::is_ascii_lowercase) {
                return false;
            }
            let mut consonants = 0;
            let mut max_consonants = 0;
            for ch in word.chars() {
                if "aeiouyAEIOUY".contains(ch) {
                    consonants = 0;
                } else {
                    consonants += 1;
                    max_consonants = max_consonants.max(consonants);
                }
            }
            max_consonants <= 3 && word.chars().any(|ch| "aeiouyAEIOUY".contains(ch))
        })
}

/// Key characters a glued key needs after its prefix.
const GLUED_MIN_TAIL: usize = 32;

/// Case and digit changes a glued key needs after its prefix.
const GLUED_MIN_TURNS: usize = 16;

/// Lower-case and upper-case letters a glued key needs after its prefix, and
/// upper-case letters not followed by a lower-case one (camelCase has none).
const GLUED_MIN_CASE: usize = 4;
const GLUED_MIN_BARE_UPPER: usize = 1;

/// Whether `tail` reads as random key characters (see [`GLUED_RE`]).
fn key_like_tail(tail: &str) -> bool {
    let class = |ch: char| match ch {
        'a'..='z' => 1,
        'A'..='Z' => 2,
        '0'..='9' => 3,
        _ => 0,
    };
    let (mut len, mut turns, mut last) = (0, 0, 0);
    let (mut lower, mut upper, mut bare_upper) = (0, 0, 0);
    for ch in tail.chars() {
        let now = class(ch);
        len += usize::from(is_key_char(ch));
        turns += usize::from(now != 0 && last != 0 && now != last);
        lower += usize::from(now == 1);
        upper += usize::from(now == 2);
        bare_upper += usize::from(last == 2 && now != 1);
        last = now;
    }
    bare_upper += usize::from(last == 2);
    len >= GLUED_MIN_TAIL
        && turns >= GLUED_MIN_TURNS
        && lower >= GLUED_MIN_CASE
        && upper >= GLUED_MIN_CASE
        // A random base62 key can have every uppercase letter followed by a
        // lowercase byte by chance. In that rare case require stronger class
        // turnover; ordinary camelCase identifiers remain below this floor.
        && (bare_upper >= GLUED_MIN_BARE_UPPER || turns >= 24)
}

/// The byte ranges of the `sk-` and `sl.` keys glued after a letter or a digit.
fn glued_keys(text: &str) -> Vec<(usize, usize)> {
    let view = KeyView::for_text(text);
    let haystack = view.as_ref().map_or(text, |view| view.text.as_str());
    let bytes = haystack.as_bytes();
    let mut out = Vec::new();
    let mut consumed = 0;
    let mut consumed_joined = JoinedKeyView::default();
    // K-SKPROJ-GLUE round 2: an exact format also counts when the run goes on
    // with `-` or `_` right after it (`<key>-prod`, `<key>_old`). The lengths
    // are `sk-` + 32, `sk-` + 48 and `sk-or-v1-` + 64; the run is ASCII.
    // An ambiguous glued prefix must first satisfy a key shape. Return the
    // issuer body only; separator tails and following identifiers stay clear.
    let key_end = |run: &str| -> Option<usize> {
        if known_glued_format(run) && !plainly_words(run) {
            return Some(run.len());
        }
        let mut best = None;
        for n in [35, 51, 56, 72, 73] {
            if run.len() >= n && known_glued_format(&run[..n]) && !plainly_words(run) {
                best = Some(best.map_or(n, |previous: usize| previous.max(n)));
            }
        }
        best
    };
    for key in GLUED_RE.find_iter(haystack) {
        let whole_run = key.as_str();
        // Prefer the first issuer-shaped prefix. A random body can itself
        // contain `sk-`; selecting its last occurrence drops real key bytes.
        let mut offset = 0;
        let mut candidate = None;
        let mut seek = 0;
        let mut checked = 0;
        while checked < 2 {
            let Some(found) = whole_run[seek..].find("sk-") else {
                break;
            };
            let at = seek + found;
            checked += 1;
            if let Some(end) = key_end(&whole_run[at..]) {
                offset = at;
                candidate = Some(end);
                break;
            }
            seek = at + 3;
        }
        let run = &whole_run[offset..];
        let start = key.start() + offset;
        let glued = start > 0 && bytes[start - 1].is_ascii_alphanumeric();
        let own_end = candidate.or_else(|| key_end(run));
        if !glued && own_end.is_none() {
            continue;
        }
        // An earlier run joined this line: an exact key is still its own key.
        if key.end() <= consumed {
            if let Some(suffix) = consumed_joined.suffix(start) {
                if let Some(suffix_end) = key_end(suffix) {
                    let end = consumed_joined.original_end();
                    let end = end - (suffix.len() - suffix_end);
                    out.push(view.as_ref().map_or((start, end), |view| {
                        let (mapped_start, _) = view.original(start, key.end());
                        let (_, end) = view.original(start, end);
                        (mapped_start, end)
                    }));
                    continue;
                }
            }
            if let Some(end) = own_end {
                out.push(view.as_ref().map_or((start, start + end), |view| {
                    view.original(start, start + end)
                }));
            }
            continue;
        }
        let end = join_wrapped(haystack, key.end(), is_key_char);
        consumed = end;
        consumed_joined = JoinedKeyView::new(haystack, start, end);
        // The run on its own line, or joined over its wrapped lines (key
        // characters only): either one may hold the exact format.
        let joined: String = haystack[start..end]
            .chars()
            .filter(|ch| is_key_char(*ch) || *ch == '.')
            .collect();
        // Prefer the complete wrapped view: a 64-byte project key can have an
        // exact 48-byte prefix on its first line, which must not truncate it.
        let accepted_end = key_end(&joined)
            .or(own_end)
            .or_else(|| key_like_tail(&haystack[start + 3..end]).then_some(end - start));
        if let Some(accepted_end) = accepted_end {
            // `accepted_end` counts key characters with wrapped line breaks
            // removed. Map its final character through the joined view so the
            // original LF/CRLF bytes are included in the masked span.
            let original_end = consumed_joined
                .ends
                .get(accepted_end.saturating_sub(1))
                .copied()
                .filter(|_| accepted_end > 0)
                .unwrap_or(start + accepted_end);
            out.push(view.as_ref().map_or((start, original_end), |view| {
                view.original(start, original_end)
            }));
        }
    }
    out
}

/// The key characters of one consumed run, with their offsets in the view that
/// `GLUED_RE` scans. Later matches inside that run can read their joined suffix
/// without walking the continuation lines again.
#[derive(Default)]
struct JoinedKeyView {
    text: String,
    starts: Vec<usize>,
    ends: Vec<usize>,
}

impl JoinedKeyView {
    fn new(source: &str, start: usize, end: usize) -> Self {
        let mut view = Self::default();
        for (offset, ch) in source[start..end].char_indices() {
            if is_key_char(ch) || ch == '.' {
                view.text.push(ch);
                view.starts.push(start + offset);
                view.ends.push(start + offset + ch.len_utf8());
            }
        }
        view
    }

    fn suffix(&self, source_start: usize) -> Option<&str> {
        let index = self.starts.binary_search(&source_start).ok()?;
        self.text.get(index..)
    }

    fn original_end(&self) -> usize {
        self.ends.last().copied().unwrap_or(0)
    }
}

/// K-GOOGLE-KEY round 2: an escaped key or a dotted `ya29.` token was read
/// before only by the gate's residue round, which masks a secret on to the
/// trimmed end of its line. Each such key keeps that run here, so no byte the
/// residue round masked is left clear. Spans are only widened, never narrowed;
/// each line end is searched once (linear).
fn to_line_ends(text: &str, spans: &mut [Span]) {
    let new_rule = |span: &Span| {
        let key = text.get(span.start..span.end).unwrap_or("");
        key.contains("\\_")
            || key.contains("\\-")
            || key
                .strip_prefix("ya29.")
                .is_some_and(|rest| rest.contains('.'))
    };
    let mut picked: Vec<&mut Span> = spans.iter_mut().filter(|span| new_rule(span)).collect();
    picked.sort_unstable_by_key(|span| span.end);
    let (mut reach, mut line, mut trimmed) = (0, usize::MAX, 0);
    for span in picked {
        let from = span.end.max(reach).min(text.len());
        let end = text[from..].find('\n').map_or(text.len(), |n| from + n);
        if end != line {
            line = end;
            trimmed = text[..line].trim_end().len();
        }
        reach = line;
        span.end = span.end.max(trimmed);
    }
}

/// FIN-6: an AWS access key ID written in lower case (`akia` and sixteen more
/// letters or digits, twenty in all). Lower case reads like prose, so unlike the
/// capital shape no ASCII letter or digit may touch it.
static LOWER_AWS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"akia[0-9a-z]{16}").expect("lower AWS key shape compiles"));

/// The byte ranges of the lower-case AWS access key IDs of `text`.
fn lower_aws_keys(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let alnum = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_alphanumeric);
    LOWER_AWS_RE
        .find_iter(text)
        .filter(|key| !(key.start() > 0 && alnum(key.start() - 1)) && !alnum(key.end()))
        .map(|key| (key.start(), key.end()))
        .collect()
}

/// The text as the key shapes read it: zero-width characters are dropped,
/// fullwidth ASCII reads as ASCII, and the dash variants (U+2010 to U+2015, U+2212)
/// read as `-`. Each kept character remembers its original byte span, so a match
/// maps back to the text.
struct KeyView {
    text: String,
    /// Per kept character: its span in `text`, then in the original.
    cuts: Vec<(usize, usize, usize, usize)>,
}

impl KeyView {
    /// The view of `text`, when a character of it folds or drops. Text without one
    /// (ASCII, or only other non-ASCII such as a masked token's stand-in) is read as
    /// it is: its view would copy the text with one entry per character.
    fn for_text(text: &str) -> Option<Self> {
        (!text.is_ascii()
            && text
                .chars()
                .any(|ch| is_default_ignorable(ch) || key_fold(ch) != ch))
        .then(|| Self::new(text))
    }

    fn new(text: &str) -> Self {
        let mut view = KeyView {
            text: String::with_capacity(text.len()),
            cuts: Vec::new(),
        };
        for (start, ch) in text.char_indices() {
            if is_default_ignorable(ch) {
                continue;
            }
            let from = view.text.len();
            view.text.push(key_fold(ch));
            view.cuts
                .push((from, view.text.len(), start, start + ch.len_utf8()));
        }
        view
    }

    /// The original byte span of the view span `start..end`.
    fn original(&self, start: usize, end: usize) -> (usize, usize) {
        let first = self
            .cuts
            .binary_search_by_key(&start, |cut| cut.0)
            .unwrap_or(0);
        let last = self
            .cuts
            .binary_search_by_key(&end, |cut| cut.1)
            .unwrap_or(self.cuts.len().saturating_sub(1));
        match (self.cuts.get(first), self.cuts.get(last)) {
            (Some(first), Some(last)) => (first.2, last.3),
            _ => (start, end),
        }
    }
}

/// The ASCII form of a key character: fullwidth ASCII and the dash variants.
fn key_fold(ch: char) -> char {
    match ch {
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
        '\u{2010}'..='\u{2015}' | '\u{2212}' => '-',
        _ => ch,
    }
}

/// Whether a character belongs to a key's alphabet.
fn is_key_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

/// The key alphabet of a JWT or an SG. key, which also has dots inside it.
fn is_dotted_key_char(ch: char) -> bool {
    is_key_char(ch) || ch == '.'
}

/// The length of the line break at `at`, including the OCR form feed and every
/// Unicode line separator the shared normalizer folds.
fn break_at(text: &str, at: usize) -> Option<usize> {
    let rest = &text[at..];
    [
        "\r\n", "\n", "\r", "\u{000b}", "\u{000c}", "\u{2028}", "\u{2029}", "\u{85}",
    ]
    .into_iter()
    .find(|line_break| rest.starts_with(line_break))
    .map(str::len)
}

/// The length of the prefix that a continuation line may open with: indentation,
/// quote and `>` markers, and the comment and bullet markers `# `, `// `, `| `
/// and `* `.
fn line_prefix_len(line: &str) -> usize {
    let bytes = line.as_bytes();
    let mut len = 0;
    loop {
        match bytes.get(len) {
            Some(b' ' | b'\t' | b'>' | b'"' | b'\'') => len += 1,
            Some(b'#' | b'|' | b'*') if bytes.get(len + 1) == Some(&b' ') => len += 2,
            Some(b'/')
                if bytes.get(len + 1) == Some(&b'/') && bytes.get(len + 2) == Some(&b' ') =>
            {
                len += 3;
            }
            _ => return len,
        }
    }
}

/// Extend a key over the lines that wrap it. Trailing spaces end a line; the next
/// line opens with an optional prefix (see [`line_prefix_len`]) and then the key
/// alphabet, which joins. A line that does not open with key characters ends the
/// key, so prose after it stays clear; so does a line whose first word is a key
/// name (`NAME=`, `NAME:`). The join is bounded by [`MAX_WRAP_BYTES`].
fn join_wrapped(text: &str, from: usize, alphabet: fn(char) -> bool) -> usize {
    let mut limit = (from + MAX_WRAP_BYTES).min(text.len());
    while !text.is_char_boundary(limit) {
        limit -= 1;
    }
    let mut end = from;
    loop {
        let spaces: usize = text[end..]
            .bytes()
            .take_while(|byte| *byte == b' ' || *byte == b'\t')
            .count();
        let at = end + spaces;
        let Some(break_len) = break_at(text, at) else {
            return end;
        };
        let line_start = at + break_len;
        if line_start >= limit {
            return end;
        }
        let run_start = line_start + line_prefix_len(&text[line_start..limit]);
        let run: usize = text[run_start..]
            .char_indices()
            .take_while(|(offset, ch)| run_start + offset < limit && alphabet(*ch))
            .map(|(_, ch)| ch.len_utf8())
            .sum();
        if run == 0 || opens_key_separator(&text[run_start + run..limit]) {
            return end;
        }
        end = run_start + run;
    }
}

/// Whether a line's text, after its key characters, opens with a key separator:
/// `:`, or `=` that is not base64 padding. Such a line is the next key in config
/// text, so a key above it does not wrap into it.
fn opens_key_separator(rest: &str) -> bool {
    rest.starts_with(':') || (rest.starts_with('=') && !rest.starts_with("=="))
}

/// An AWS secret access key or session token, matched by its key name in env,
/// ini, JSON and YAML (`SecretAccessKey`, `secret_access_key = "…"`,
/// `AWS_SECRET_KEY=`, a YAML folded value). Only the value is the secret.
static AWS_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:(?:aws_?)?secret_?access_?key|aws_?secret_?key|aws_session_token)["']?\s*[:=]\s*[>|]?\s*["']?([A-Za-z0-9/+=_\-]{20,})"#,
    )
    .expect("aws secret key shape compiles")
});

/// Longest key token read before a separator, in bytes. A key name is found within
/// this many bytes of its separator; nothing further back is read.
const MAX_KEY_BYTES: usize = 64;

/// Longest value read up to its own end, in bytes. A longer one is the whole remainder
/// of its line, masked as one secret: over-masked, never refused, never masked in part.
const MAX_VALUE_BYTES: usize = 1024;

/// Longest YAML block scalar the gate reads, in bytes. A longer one is refused too.
const MAX_BLOCK_BYTES: usize = 8192;

/// Longest quoted value read up to its closing quote, in bytes. The quote may close
/// on a later line.
const MAX_QUOTED_BYTES: usize = 8192;

/// Longest word read when a blank is tested for starting another assignment, in bytes.
const MAX_TERMINATOR_WORD: usize = 128;

/// Bytes before a separator read for a spaced or non-ASCII key name.
const KEY_TAIL_BYTES: usize = 40;

/// Most key segments joined when testing a key name.
const MAX_NAME_SEGMENTS: usize = 4;

/// Shortest value (blanks not counted) of a password key. Other secret keys take any
/// non-empty value.
const MIN_PASSWORD_LENGTH: usize = 4;

/// The class of a key: a password, or another secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyClass {
    Password,
    Other,
}

/// Key names that match a segment of a key, or a run of segments joined by `_`:
/// `SECRET_KEY` has the segment `secret`, `APP_KEY` the run `app_key`.
const KEY_NAMES: &[(&str, KeyClass)] = &[
    ("password", KeyClass::Password),
    ("passwd", KeyClass::Password),
    ("pwd", KeyClass::Password),
    ("pass", KeyClass::Password),
    ("passphrase", KeyClass::Password),
    ("mdp", KeyClass::Password),
    ("mot_de_passe", KeyClass::Password),
    ("motdepasse", KeyClass::Password),
    ("jelszo", KeyClass::Password),
    ("geslo", KeyClass::Password),
    ("wagwoord", KeyClass::Password),
    ("secret", KeyClass::Other),
    ("token", KeyClass::Other),
    ("api_key", KeyClass::Other),
    ("apikey", KeyClass::Other),
    ("access_key", KeyClass::Other),
    ("private_key", KeyClass::Other),
    ("client_secret", KeyClass::Other),
    ("encryption_key", KeyClass::Other),
    ("master_key", KeyClass::Other),
    ("app_key", KeyClass::Other),
    ("auth_token", KeyClass::Other),
    ("credential", KeyClass::Other),
    ("credentials", KeyClass::Other),
    ("dsn", KeyClass::Other),
];

/// Key names that match the text before the separator: spaced and non-ASCII names.
const KEY_PHRASES: &[(&str, KeyClass)] = &[
    ("mot de passe", KeyClass::Password),
    ("jelszó", KeyClass::Password),
    ("密码", KeyClass::Password),
    ("密碼", KeyClass::Password),
    ("口令", KeyClass::Password),
];

/// A secret-class value: its byte span in the scanned text, and whether it is past
/// the length the gate reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SecretValue {
    start: usize,
    end: usize,
    long: bool,
}

/// The segments of a key token, split at `_`, `.`, `-` and at camelCase boundaries
/// (`secretKey` and `APIKey` split too). Slices of the token: a key costs one
/// allocation.
fn key_segments(token: &str) -> Vec<&str> {
    let bytes = token.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if matches!(byte, b'_' | b'.' | b'-') {
            if index > start {
                segments.push(&token[start..index]);
            }
            start = index + 1;
        } else if byte.is_ascii_uppercase() && index > start {
            let before = bytes[index - 1];
            let acronym_end = before.is_ascii_uppercase()
                && bytes.get(index + 1).is_some_and(u8::is_ascii_lowercase);
            if before.is_ascii_lowercase() || before.is_ascii_digit() || acronym_end {
                segments.push(&token[start..index]);
                start = index;
            }
        }
    }
    if start < bytes.len() {
        segments.push(&token[start..]);
    }
    segments
}

/// Whether a run of up to [`MAX_NAME_SEGMENTS`] segments, joined by `_`, is `name`
/// (ASCII case ignored).
fn segments_contain(segments: &[&str], name: &str) -> bool {
    (0..segments.len()).any(|first| {
        let mut rest = name;
        for (offset, segment) in segments[first..].iter().take(MAX_NAME_SEGMENTS).enumerate() {
            if offset > 0 {
                let Some(next) = rest.strip_prefix('_') else {
                    return false;
                };
                rest = next;
            }
            let Some(head) = rest.get(..segment.len()) else {
                return false;
            };
            if !head.eq_ignore_ascii_case(segment) {
                return false;
            }
            rest = &rest[segment.len()..];
            if rest.is_empty() {
                return true;
            }
        }
        false
    })
}

/// The class of a key token by the key names it carries. A password name wins.
fn name_class(token: &str) -> Option<KeyClass> {
    let segments = key_segments(token);
    let mut found = None;
    for &(name, class) in KEY_NAMES {
        if segments_contain(&segments, name) {
            if class == KeyClass::Password {
                return Some(KeyClass::Password);
            }
            found = Some(class);
        }
    }
    found
}

/// The class of the text before a separator, by a spaced or non-ASCII key name. The
/// window is `text[window..end]`; an ASCII window is compared without a copy.
fn phrase_class(text: &str, window: usize, end: usize) -> Option<KeyClass> {
    let tail = &text[window..end];
    if tail.is_ascii() {
        KEY_PHRASES
            .iter()
            .find(|entry| {
                let phrase = entry.0;
                phrase.is_ascii()
                    && tail.len() >= phrase.len()
                    && tail[tail.len() - phrase.len()..].eq_ignore_ascii_case(phrase)
            })
            .map(|entry| entry.1)
    } else {
        let lower = tail.to_lowercase();
        KEY_PHRASES
            .iter()
            .find(|entry| lower.ends_with(entry.0))
            .map(|entry| entry.1)
    }
}

/// The key before the separator at `sep`: blanks and up to [`MAX_KEY_MARKS`] closing
/// marks (a JSON or curly quote, a backtick, Markdown `*` or `_`) are skipped, then
/// the ASCII key characters (at most [`MAX_KEY_BYTES`]) are read and matched.
fn key_before(text: &str, sep: usize) -> Option<KeyClass> {
    let bytes = text.as_bytes();
    let mut end = skip_back_blanks(bytes, sep);
    let mut marks = 0;
    while marks < MAX_KEY_MARKS {
        let Some(mark) = text[..end]
            .chars()
            .next_back()
            .filter(|ch| is_key_mark(*ch))
        else {
            break;
        };
        end -= mark.len_utf8();
        marks += 1;
    }
    if marks > 0 {
        end = skip_back_blanks(bytes, end);
    }
    let mut start = end;
    while start > 0 && end - start < MAX_KEY_BYTES && is_key_byte(bytes[start - 1]) {
        start -= 1;
    }
    let token = &text[start..end];
    let mut class = name_class(token);
    // A spaced or non-ASCII name ends the text before the separator. Only a word that
    // ends the phrase (`passe` of `mot de passe`), or no word at all, can end one.
    if token.is_empty() || token.eq_ignore_ascii_case("passe") {
        let mut window = end.saturating_sub(KEY_TAIL_BYTES);
        while !text.is_char_boundary(window) {
            window += 1;
        }
        if class != Some(KeyClass::Password) {
            class = phrase_class(text, window, end).or(class);
        }
    }
    class
}

/// The most closing marks read between a key and its separator (`**password**:`).
const MAX_KEY_MARKS: usize = 3;

/// A mark that may close a key: a straight or curly quote, a guillemet, a backtick,
/// or Markdown emphasis.
fn is_key_mark(ch: char) -> bool {
    matches!(
        ch,
        '"' | '\''
            | '`'
            | '*'
            | '_'
            | '\u{201c}'
            | '\u{201d}'
            | '\u{2018}'
            | '\u{2019}'
            | '\u{ab}'
            | '\u{bb}'
    )
}

fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

fn is_blank(ch: char) -> bool {
    ch == ' ' || ch == '\t'
}

/// The index after the blanks (spaces and tabs) that start at `at`.
fn skip_blanks(bytes: &[u8], mut at: usize) -> usize {
    while at < bytes.len() && matches!(bytes[at], b' ' | b'\t') {
        at += 1;
    }
    at
}

/// The index before the blanks that end at `at`.
fn skip_back_blanks(bytes: &[u8], mut at: usize) -> usize {
    while at > 0 && matches!(bytes[at - 1], b' ' | b'\t') {
        at -= 1;
    }
    at
}

/// The length of the separator at `at`: `:=` (Go) and `=>` (PHP, Ruby) are two
/// bytes; `:`, `=` and `：` are one.
fn separator_len(text: &str, at: usize) -> Option<usize> {
    let rest = &text[at..];
    if rest.starts_with(":=") || rest.starts_with("=>") {
        Some(2)
    } else if rest.starts_with([':', '=', '：']) {
        rest.chars().next().map(char::len_utf8)
    } else {
        None
    }
}

/// Whether a value is a YAML block-scalar header: `|` or `>`, then `-`, `+` or digits.
fn is_block_header(value: &str) -> bool {
    let mut chars = value.chars();
    value.len() <= 4
        && matches!(chars.next(), Some('|' | '>'))
        && chars.all(|ch| matches!(ch, '-' | '+' | '0'..='9'))
}

/// Line breaks of a text, indexed once. A value finds its line end by binary search,
/// so a long line with many values stays linear.
struct Breaks {
    /// Byte offsets of every LF.
    newlines: Vec<usize>,
    /// Byte offsets of every line break: LF, CR, U+2028 and U+85.
    all: Vec<usize>,
    len: usize,
}

impl Breaks {
    /// One pass over the bytes: the byte forms of U+2028 and U+85 are checked only at
    /// their lead byte.
    fn new(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut newlines = Vec::new();
        let mut all = Vec::new();
        for (at, &byte) in bytes.iter().enumerate() {
            match byte {
                b'\n' => {
                    newlines.push(at);
                    all.push(at);
                }
                b'\r' => all.push(at),
                0xE2 if bytes[at..].starts_with("\u{2028}".as_bytes()) => all.push(at),
                0xC2 if bytes[at..].starts_with("\u{85}".as_bytes()) => all.push(at),
                _ => {}
            }
        }
        Self {
            newlines,
            all,
            len: text.len(),
        }
    }

    /// The first LF at or after `from`, or the text end.
    fn newline_from(&self, from: usize) -> usize {
        self.newlines
            .get(self.newlines.partition_point(|&at| at < from))
            .copied()
            .unwrap_or(self.len)
    }

    /// The first line break of any kind at or after `from`, or the text end.
    fn break_from(&self, from: usize) -> usize {
        self.all
            .get(self.all.partition_point(|&at| at < from))
            .copied()
            .unwrap_or(self.len)
    }

    /// The start of the line that holds `at`.
    fn line_start(&self, at: usize) -> usize {
        match self.newlines.partition_point(|&stop| stop < at) {
            0 => 0,
            index => self.newlines[index - 1] + 1,
        }
    }
}

/// The value after a separator, on its line, with the end of its unbounded remainder
/// (the rest of the line, which decides the minimum length). A quoted value ends at
/// its matching closing quote, even on a later line, within [`MAX_QUOTED_BYTES`]. An
/// unquoted one ends at the first of: the line end, a `&` that starts a query
/// parameter, or a blank that starts another assignment or flag. A value past
/// [`MAX_VALUE_BYTES`] is the whole remainder of its line, masked as one secret. A
/// line with no value, or a block-scalar header, takes the lines indented under the
/// key instead.
fn rest_value(
    text: &str,
    breaks: &Breaks,
    sep: usize,
    after: usize,
) -> Option<(SecretValue, usize)> {
    let bytes = text.as_bytes();
    // Only LF ends a value's line: a lone CR or U+2028 stays inside the value.
    let line_stop = breaks.newline_from(after);
    let start = skip_blanks(bytes, after);
    let rest = text[start..line_stop].trim_end_matches(is_trailing_blank);
    if rest.is_empty() || is_block_header(rest) {
        let block = block_value(text, breaks, sep, breaks.break_from(after))?;
        return Some((block, block.end));
    }
    if let Some(end) = quoted_end(text, start) {
        let value = SecretValue {
            start,
            end,
            long: false,
        };
        return Some((value, line_stop.max(end)));
    }
    let end = item_end(text, start, unquoted_end(text, start, line_stop));
    let end = if end - start > MAX_VALUE_BYTES {
        start + rest.len()
    } else {
        end
    };
    if end == start {
        return None;
    }
    let value = SecretValue {
        start,
        end,
        long: false,
    };
    Some((value, start + rest.len()))
}

/// The end, after its closing quote, of a quoted value that opens at `open`. A double
/// quote takes a backslash escape; a single quote takes YAML's doubled `''`. The quote
/// may close on a later line, within [`MAX_QUOTED_BYTES`]. `None` when `open` is not
/// a quote, or the quote does not close in that span.
fn quoted_end(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let quote = match bytes.get(open) {
        Some(&byte @ (b'"' | b'\'')) => byte,
        _ => return None,
    };
    let limit = bytes.len().min(open + 1 + MAX_QUOTED_BYTES);
    let mut at = open + 1;
    while at < limit {
        match bytes[at] {
            b'\\' if quote == b'"' => at += 2,
            byte if byte == quote => {
                if quote == b'\'' && at + 1 < limit && bytes[at + 1] == b'\'' {
                    at += 2;
                } else {
                    return Some(at + 1);
                }
            }
            _ => at += 1,
        }
    }
    None
}

/// The raw end of an unquoted value at `start`: the line end, a `&` that starts a
/// query parameter, or the blank that starts another assignment or flag. The search
/// stops one byte past [`MAX_VALUE_BYTES`]: a value with no end inside that span is
/// over the cap, and the caller masks its whole remainder. The first character is
/// part of the value.
fn unquoted_end(text: &str, start: usize, line_stop: usize) -> usize {
    let bytes = text.as_bytes();
    let window = line_stop.min(start + MAX_VALUE_BYTES + 1);
    let mut at = start + text[start..].chars().next().map_or(1, char::len_utf8);
    let mut after_blank = false;
    while at < window {
        match bytes[at] {
            b'&' if is_query_parameter(&text[at + 1..line_stop]) => return at,
            b' ' | b'\t' => {
                if !after_blank
                    && starts_assignment_or_flag(&text[skip_blanks(bytes, at)..line_stop])
                {
                    return at;
                }
                after_blank = true;
            }
            _ => after_blank = false,
        }
        at += 1;
    }
    line_stop
}

/// Whether a byte belongs to a key or query-parameter name.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'[' | b']')
}

/// Whether `rest` (the text after a `&`) opens a query parameter: a name of letters,
/// digits and `_ . - [ ]` that starts with a letter or `_`, then `=`.
fn is_query_parameter(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    let name = bytes
        .iter()
        .take(MAX_TERMINATOR_WORD)
        .take_while(|&&byte| is_name_byte(byte))
        .count();
    name > 0
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes.get(name) == Some(&b'=')
}

/// Whether `rest` opens another assignment or flag: `-e` as its own word, `--flag`,
/// or a word of two or more characters (`[A-Za-z_][A-Za-z0-9_.-]*`) followed by `=`
/// or `:`, and then not by another `=`. A `=` at the end of the line does not count,
/// so base64 padding (`abc==`) never ends a value.
fn starts_assignment_or_flag(rest: &str) -> bool {
    if let Some(after) = rest.strip_prefix("-e") {
        if after.is_empty() || after.starts_with(is_blank) {
            return true;
        }
    }
    if let Some(after) = rest.strip_prefix("--") {
        if after.starts_with(|ch: char| ch.is_ascii_alphabetic()) {
            return true;
        }
    }
    let bytes = rest.as_bytes();
    let word = bytes
        .iter()
        .take(MAX_TERMINATOR_WORD)
        .take_while(|&&byte| is_name_byte(byte) && byte != b'[' && byte != b']')
        .count();
    if word < 2 || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return false;
    }
    match bytes.get(word) {
        Some(b':') => bytes.get(word + 1) != Some(&b'='),
        Some(b'=') => !matches!(bytes.get(word + 1), None | Some(b'=' | b'\r' | b'\n')),
        _ => false,
    }
}

/// The end of an unquoted value: its trailing blanks and CR are not part of it, and
/// one `,` or `;` before them ends a JSON or INI item.
fn item_end(text: &str, start: usize, end: usize) -> usize {
    let trimmed = |end: usize| start + text[start..end].trim_end_matches(is_trailing_blank).len();
    let end = trimmed(end);
    if end > start && matches!(text.as_bytes()[end - 1], b',' | b';') {
        trimmed(end - 1)
    } else {
        end
    }
}

/// Whether a character is trailing noise on a value's line: a blank or a CR.
fn is_trailing_blank(ch: char) -> bool {
    ch == ' ' || ch == '\t' || ch == '\r'
}

/// The block under a key: the lines below the key line that are indented deeper than
/// the key line, blank lines included. The first line that is not deeper ends it.
fn block_value(
    text: &str,
    breaks: &Breaks,
    sep: usize,
    key_line_stop: usize,
) -> Option<SecretValue> {
    let bytes = text.as_bytes();
    let key_line = breaks.line_start(sep);
    let indent = skip_blanks(bytes, key_line) - key_line;
    let mut line = key_line_stop + break_at(text, key_line_stop)?;
    let mut first: Option<usize> = None;
    let mut last = 0;
    while line < bytes.len() {
        let end = breaks.break_from(line);
        let content = skip_blanks(bytes, line);
        if content < end {
            if content - line <= indent {
                break;
            }
            if first.is_none() {
                first = Some(content);
            }
            last = end;
        }
        match break_at(text, end) {
            Some(len) => line = end + len,
            None => break,
        }
    }
    let start = first?;
    Some(SecretValue {
        start,
        end: last,
        long: last - start > MAX_BLOCK_BYTES,
    })
}

/// The key-value secrets: every separator whose key before it is secret-class, with the
/// value after it. A password value needs [`MIN_PASSWORD_LENGTH`] characters in its
/// whole unbounded remainder, so a cut at a terminator never drops a value.
fn key_values(text: &str) -> Vec<SecretValue> {
    let breaks = Breaks::new(text);
    let mut values = Vec::new();
    // A value holds the separators inside it: they start no new key.
    let mut resume = 0;
    for (sep, _) in text.char_indices() {
        if sep < resume {
            continue;
        }
        let Some(len) = separator_len(text, sep) else {
            continue;
        };
        // The key is checked before any value is read.
        let Some(class) = key_before(text, sep) else {
            continue;
        };
        let Some((value, remainder)) = rest_value(text, &breaks, sep, sep + len) else {
            continue;
        };
        if class == KeyClass::Password
            && text[value.start..remainder]
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .take(MIN_PASSWORD_LENGTH)
                .count()
                < MIN_PASSWORD_LENGTH
        {
            continue;
        }
        resume = value.end;
        values.push(value);
    }
    values
}

/// Byte spans of the lines of `text`, without their line break. A CRLF is one break,
/// and a lone CR, U+2028 or U+85 is a break too.
fn line_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    while let Some(offset) = text[start..].find(['\n', '\r', '\u{2028}', '\u{85}']) {
        let stop = start + offset;
        spans.push((start, stop));
        start = stop + break_at(text, stop).unwrap_or(1);
    }
    spans.push((start, text.len()));
    spans
}

/// A Kubernetes secret env pair: a `- name: <secret-class NAME>` line, then a
/// `value: <x>` line within the next two lines. Only `x` is the secret.
fn k8s_values(text: &str) -> Vec<SecretValue> {
    if !text.contains("name:") {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let lines = line_spans(text);
    let mut values = Vec::new();
    for (index, &(line_start, line_stop)) in lines.iter().enumerate() {
        let mut at = skip_blanks(bytes, line_start);
        if at < line_stop && bytes[at] == b'-' {
            at = skip_blanks(bytes, at + 1);
        }
        if !text[at..line_stop].starts_with("name:") {
            continue;
        }
        let name_start = skip_blanks(bytes, at + "name:".len());
        let name = text[name_start..line_stop]
            .trim_end_matches(is_trailing_blank)
            .trim_matches(|ch: char| ch == '"' || ch == '\'');
        if name.is_empty() || !name.bytes().all(is_key_byte) || name_class(name).is_none() {
            continue;
        }
        for &(next_start, next_stop) in lines.iter().skip(index + 1).take(2) {
            let content = skip_blanks(bytes, next_start);
            if !text[content..next_stop].starts_with("value:") {
                continue;
            }
            let start = skip_blanks(bytes, content + "value:".len());
            let end = start
                + text[start..next_stop]
                    .trim_end_matches(is_trailing_blank)
                    .len();
            if end > start {
                values.push(SecretValue {
                    start,
                    end,
                    long: false,
                });
            }
            break;
        }
    }
    values
}

/// An XML or HTML element whose tag name is secret-class, on one line:
/// `<password>…</password>`. Only its text is the secret.
static XML_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<([A-Za-z][A-Za-z0-9_.:-]*)(?:[ \t][^<>\r\n]*)?>([^<\r\n]+)</[^>\r\n]*>")
        .expect("xml secret shape compiles")
});

fn xml_values(text: &str) -> Vec<SecretValue> {
    if !text.contains("</") {
        return Vec::new();
    }
    XML_SECRET_RE
        .captures_iter(text)
        .filter_map(|captures| {
            let name = captures.get(1)?;
            name_class(name.as_str())?;
            let content = captures.get(2)?;
            let raw = content.as_str();
            let trimmed = raw.trim_matches(is_blank);
            if trimmed.is_empty() {
                return None;
            }
            let start = content.start() + (raw.len() - raw.trim_start_matches(is_blank).len());
            Some(SecretValue {
                start,
                end: start + trimmed.len(),
                long: false,
            })
        })
        .collect()
}

/// A command-line secret: `--password value`, `--password=value`, for the flags
/// `password`, `passwd`, `token`, `api-key`, `secret` and `client-secret`. The value
/// is the next token; a value that opens with a quote runs to its matching closing
/// quote, so `"correct horse battery"` is one secret.
static CLI_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)--(password|passwd|token|api-key|secret|client-secret)(?:=|[ \t]+)("(?:\\.|[^"\\\r\n])*"|'[^'\r\n]*'|"[^\r\n]*|'[^\r\n]*|\S+)"#,
    )
    .expect("cli secret shape compiles")
});

fn cli_values(text: &str) -> Vec<SecretValue> {
    if !text.contains("--") {
        return Vec::new();
    }
    CLI_SECRET_RE
        .captures_iter(text)
        .filter_map(|captures| {
            let flag = captures.get(1)?.as_str();
            let value = captures.get(2)?;
            let password =
                flag.eq_ignore_ascii_case("password") || flag.eq_ignore_ascii_case("passwd");
            if password
                && value
                    .as_str()
                    .chars()
                    .filter(|ch| !ch.is_whitespace())
                    .count()
                    < MIN_PASSWORD_LENGTH
            {
                return None;
            }
            Some(SecretValue {
                start: value.start(),
                end: value.end(),
                long: false,
            })
        })
        .collect()
}

/// The key of a prose secret (K13): a password, a passcode, or a key or token, with
/// the closed key set and a whole-word match, in any case. The link is an optional
/// `is`, `was`, `of`, `=`, `:` or `->`, after up to three Markdown or quote marks
/// closing the key (`**password**:`, `` `password` is ``), and the value is the next word on the line,
/// after an optional quote. A key and its value stay on one line.
static PROSE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:\b|_)(?:passwd|password|pwd|passcode|passphrase|api[ -]key|apikey|secret key|access key|access token|auth token|private key)(?:\b[*_`"'”’»]{0,3}|_{1,3}[*`"'”’»]{0,2})(?:[ \t]+(?:is|was|of)[ \t]+|[ \t]*(?:=|:|->)[*_`]{0,3}[ \t]*|[ \t]+)["'“‘«]?([^\s]+)"#,
    )
    .expect("prose secret shape compiles")
});

/// A key name wrapped in marks (`` `token` is X ``, `“clientSecret” was X`,
/// `__api_key__ is X`), K15: the marks show it is a name, so any name that the
/// name-assigned rule classes as a secret key takes an `is` or `was` link. Group 1
/// is the name, group 2 the value.
static DECORATED_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"[*_`"'“‘«]{1,3}([A-Za-z][A-Za-z0-9_.\- ]{0,62}[A-Za-z0-9])[*_`"'”’»]{1,3}[ \t]+(?i:is|was)[ \t]+["'“‘«]?([^\s]+)"#,
    )
    .expect("decorated key shape compiles")
});

/// Words that follow a prose key and are not its value (K13): a status, a function
/// word, or the head of a noun phrase such as `password manager`.
const PROSE_STOPWORDS: &[&str] = &[
    "is",
    "was",
    "are",
    "required",
    "incorrect",
    "invalid",
    "expired",
    "wrong",
    "missing",
    "reset",
    "changed",
    "updated",
    "manager",
    "field",
    "policy",
    "protected",
    "here",
    "below",
    "above",
    "for",
    "to",
    "and",
    "or",
    "the",
    "a",
    "an",
    "not",
    "will",
    "must",
    "should",
    "can",
];

/// A value word without the punctuation and closing quote that follow it.
fn value_word(word: &str) -> &str {
    word.trim_end_matches(['.', ',', ';', ')', ']', '"', '\''])
}

/// A value word without any closing mark, only to compare it with a stopword: the
/// masked span keeps the marks, which may be part of the secret (K15 seal r1).
fn bare_word(word: &str) -> &str {
    value_word(word).trim_end_matches(['`', '*', '_', '}', '\u{201d}', '\u{2019}', '\u{bb}'])
}

/// Whether a value word is long enough to be a secret (K13).
fn is_value_word(word: &str) -> bool {
    word.chars().count() >= MIN_PASSWORD_LENGTH
}

/// The values of the prose rule (K13): the word after a prose key, unless it is a
/// stopword or too short.
fn prose_values(text: &str) -> (Vec<SecretValue>, Vec<SecretValue>) {
    let breaks = Breaks::new(text);
    let (phrase, mut tails) = phrase_scan(text, &breaks);
    let extra = key_tail_scan(text, &breaks);
    let named = DECORATED_KEY_RE.captures_iter(text).filter_map(|captures| {
        let name = captures.get(1)?.as_str().replace(' ', "_");
        name_class(&name).and(captures.get(2))
    });
    let mut values: Vec<SecretValue> = PROSE_KEY_RE
        .captures_iter(text)
        .filter_map(|captures| captures.get(1))
        .chain(named)
        .filter_map(|value| {
            let word = value_word(value.as_str());
            let stopword = PROSE_STOPWORDS
                .iter()
                .any(|stop| stop.eq_ignore_ascii_case(bare_word(word)));
            // The key rule masks exactly what main masked (seal r3: any exclusion
            // list let real values through); the phrase rule below only adds.
            if stopword || !is_value_word(word) {
                return None;
            }
            Some(SecretValue {
                start: value.start(),
                end: value.start() + word.len(),
                long: word.len() > MAX_VALUE_BYTES,
            })
        })
        .chain(phrase)
        .collect();
    // Both shapes may find the same value: keep it once.
    values.sort_by_key(|value| (value.start, value.end));
    values.dedup_by_key(|value| (value.start, value.end));
    // A K-SECRET-TAIL-2 span equal to a value is that value: kept once.
    let key = |value: &SecretValue| (value.start, value.end);
    tails.extend(
        extra
            .into_iter()
            .filter(|span| values.binary_search_by_key(&key(span), key).is_err()),
    );
    (values, tails)
}

/// Whether a value with no link before it looks like a secret rather than a word: it
/// has a digit, a character that is not a letter, or a capital after its first letter.
fn is_secret_shaped(word: &str) -> bool {
    word.chars()
        .enumerate()
        .any(|(index, ch)| !ch.is_alphabetic() || (index > 0 && ch.is_uppercase()))
}

/// The cue of a secret in a sentence (K-SECRET-PHRASE): a password word, a key or token
/// name, a passcode, a PIN, a door or alarm code, `pw`, `pass` or `code`, as a whole word
/// in any case. Group 1 is set for `passwords`, which also links with `are`; group 2 for
/// a passphrase, whose value runs to the clause end; group 3 for a weak cue, whose value
/// needs a digit; group 4 for `code`, which counts only with a qualifier (`the code to
/// the shared drive: …`); group 5 for `token`, whose value must look like one.
static PHRASE_CUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:(passwords)|password|passwd|(passphrase|seed phrase|recovery phrase)|pwd|api[ -]?key|secret key|access key|access token|auth token|private key|(passcode|pass|pw|pin(?: number| code)?|(?:door|alarm|gate|access) code|(code)|(token)))\b",
    )
    .expect("phrase cue shape compiles")
});

/// Most words, and bytes after the cue, of the qualifier between a cue and its link
/// (`for the client portal`). The same caps bound the filler between `is` and a later
/// colon (`the same as before:`). Nothing further is read.
const MAX_QUALIFIER_WORDS: usize = 8;
const MAX_QUALIFIER_BYTES: usize = 80;

/// Most values read in a list after `passwords` (`are A and B`).
const MAX_LIST_VALUES: usize = 4;

/// Words that may stand between a link and its value (`is now …`); one is skipped.
const FILLERS: &str = "now still just also actually currently simply";

/// Words that make `password <word>:` a label, not a value (`password strength: Strong`).
const LABELS: &str = "strength policy requirements rules hint reset manager length";

/// Whether `word` is one of the space-separated `words`, in any case.
pub(super) fn one_of(words: &str, word: &str) -> bool {
    words.split(' ').any(|one| one.eq_ignore_ascii_case(word))
}

fn is_label(word: &str) -> bool {
    one_of(LABELS, word.trim_end_matches([':', '=', '：']))
}

/// Longest quoted value read up to its closing quote on the same line, in bytes.
const MAX_PHRASE_QUOTE_BYTES: usize = 128;

/// The words that open a qualifier.
const QUALIFIER_HEADS: &[&str] = &["for", "to", "of", "on", "at", "in", "with", "from"];

/// The next word at or after `at` and before `stop`, blanks skipped: it runs to the
/// next whitespace, and reads at most `cap` bytes plus one character.
fn next_word(text: &str, at: usize, stop: usize, cap: usize) -> Option<(usize, usize)> {
    let start = skip_blanks(text.as_bytes(), at);
    let mut end = start;
    for ch in text.get(start..stop)?.chars() {
        if ch.is_whitespace() || end - start > cap {
            break;
        }
        end += ch.len_utf8();
    }
    (end > start).then_some((start, end))
}

/// How a word links a cue to its value: `is` or `was`, or a separator (`:`, `=`, `->`,
/// or a word that ends with `:` or `=`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Link {
    Is,
    Separator,
}

fn link_of(word: &str, plural: bool) -> Option<Link> {
    let plural_link = word.eq_ignore_ascii_case("are") || word.eq_ignore_ascii_case("were");
    if word.eq_ignore_ascii_case("is") || word.eq_ignore_ascii_case("was") || plural && plural_link
    {
        Some(Link::Is)
    } else if matches!(word, "->" | "=>") || word.ends_with([':', '=', '：']) {
        Some(Link::Separator)
    } else {
        None
    }
}

/// What a value needs besides its length: nothing, a digit, or a token's shape (a digit,
/// a letter and eight characters).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Any,
    Digit,
    Token,
}

/// The value that opens at `at`, before `stop`: a quoted run up to its closing quote on
/// the line (within [`MAX_PHRASE_QUOTE_BYTES`]), without the quotes, or else the next
/// word without its closing punctuation. Kept when it is no stopword, has
/// [`MIN_PASSWORD_LENGTH`] characters, what `need` asks, and a secret's shape when
/// `shaped`. The second item is where the read stopped.
fn phrase_value(
    text: &str,
    at: usize,
    stop: usize,
    need: Need,
    shaped: bool,
) -> (Option<SecretValue>, usize) {
    let Some((start, end)) = next_word(text, at, stop, MAX_VALUE_BYTES) else {
        return (None, at);
    };
    let open = text[start..]
        .chars()
        .next()
        .filter(|ch| "\"'“‘«".contains(*ch));
    let quoted = open.and_then(|open| {
        let inner = start + open.len_utf8();
        let close = match open {
            '“' => '”',
            '‘' => '’',
            '«' => '»',
            other => other,
        };
        let mut limit = stop.min(inner + MAX_PHRASE_QUOTE_BYTES);
        while !text.is_char_boundary(limit) {
            limit -= 1;
        }
        let found = text[inner..limit].find(close)?;
        Some((inner, inner + found))
    });
    let (start, value_end, read) = match quoted {
        Some((inner, close)) => (inner, close, close),
        None => {
            let skip = open.map_or(0, char::len_utf8);
            let word = value_word(&text[start + skip..end]);
            (start + skip, start + skip + word.len(), end)
        }
    };
    let value = &text[start..value_end];
    let stopword = PROSE_STOPWORDS
        .iter()
        .any(|stop| stop.eq_ignore_ascii_case(bare_word(value)));
    let kept = !stopword
        && value.chars().filter(|ch| !ch.is_whitespace()).count() >= MIN_PASSWORD_LENGTH
        && (need == Need::Any || value.chars().any(|ch| ch.is_ascii_digit()))
        && (need != Need::Token || value.len() >= 8 && value.chars().any(char::is_alphabetic))
        && (!shaped || is_secret_shaped(value));
    let value = kept.then_some(SecretValue {
        start,
        end: value_end,
        long: value_end - start > MAX_VALUE_BYTES,
    });
    (value, read)
}

/// The values of secrets written in a sentence (K-SECRET-PHRASE). After a cue comes
/// either a value that looks like a secret (`pass Gx7#qq91`), or an optional qualifier
/// that opens with a [`QUALIFIER_HEADS`] word (at most [`MAX_QUALIFIER_WORDS`] words
/// ending within [`MAX_QUALIFIER_BYTES`] bytes of the cue), a link, and the value. When
/// the word after `is` is not a value, a word ending in `:` within the same caps may
/// still bring one that looks like a secret (`is the same as before: Sunflower#88`).
/// Cue, link and value stay on one line. A cue inside a value already read is skipped,
/// so the scan stays linear.
/// Adds the clause tail of `value`: from its end to its clause end (`. , ; ! ?` or the
/// line break `stop`), with no byte cap; past [`MAX_VALUE_BYTES`] from the value it is
/// long and the gate refuses the text (fail closed). A value ending inside the last
/// tail shares its clause end and adds nothing, so the scan stays linear.
fn push_tail(
    text: &str,
    value: Option<&SecretValue>,
    stop: usize,
    tails: &mut Vec<SecretValue>,
    tail_reach: &mut usize,
) {
    let Some(value) = value.filter(|value| value.end > *tail_reach) else {
        return;
    };
    let clause = text[value.start..stop]
        .split(['.', ',', ';', '!', '?'])
        .next()
        .unwrap_or("")
        .trim_end();
    let end = value.start + clause.len();
    // From the value's end, so value and tail are one contiguous masked run.
    let start = value.end.min(end);
    if end > start {
        tails.push(SecretValue {
            start,
            end,
            long: end - value.start > MAX_VALUE_BYTES,
        });
    }
    *tail_reach = (*tail_reach).max(end);
}

/// French words that open a qualifier (`mot de passe du portail`, `pour le site`).
const FRENCH_HEADS: &str = "du de des pour sur au à";

/// French words that may stand between a link and the value; one is skipped.
const FRENCH_FILLERS: &str = "maintenant toujours désormais actuellement bien";

/// French words after a link that are not a value: a status or a function word.
const FRENCH_STOPWORDS: &str = "oublié oubliée incorrect incorrecte invalide expiré expirée \
     requis requise obligatoire faux fausse erroné erronée changé changée modifié modifiée \
     perdu perdue bloqué bloquée trop vide court courte long longue nécessaire différent \
     pareil même ici dans pour votre notre cette celui celle";

/// The keys whose value may run to its clause end (K-SECRET-TAIL-2): the cues of
/// [`PHRASE_CUE_RE`] that take any value, and the French `mot de passe` and `mdp`. A
/// `-` or `_` between key words reads as a space (`mot-de-passe`). The word edges are
/// checked by [`key_tail_scan`], so emphasis may touch the key (`__password__`). It
/// reads the text in ASCII lower case, so its literals stay fast to find.
static TAIL_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"password|passwd|pwd|passphrase|(?:seed|recovery)[ \t_-]+phrase|api[ \t_-]?key|(?:secret|access|private)[ \t_-]+key|(?:access|auth)[ \t_-]+token|mot[ \t_-]+de[ \t_-]+passe|mdp",
    )
    .expect("tail key shape compiles")
});

/// Most emphasis marks skipped after a tail key (`**~~pwd~~**`).
const MAX_EMPHASIS: usize = 4;

/// A Markdown emphasis or code mark, or a closing quote (`*`, `_`, `` ` ``, `~`, `”`).
fn is_emphasis(ch: char) -> bool {
    ch == '~' || is_key_mark(ch)
}

/// `at` moved past a run of at most [`MAX_EMPHASIS`] emphasis marks.
fn skip_emphasis(text: &str, at: usize) -> usize {
    let marks = text[at..]
        .chars()
        .take(MAX_EMPHASIS)
        .take_while(|&ch| is_emphasis(ch));
    at + marks.map(char::len_utf8).sum::<usize>()
}

/// Whether `word`, its emphasis aside, links a tail key to its value: `is`, `was`,
/// `est`, `était`, or a bare separator (`: `, `**Password:**`).
fn is_tail_link(word: &str) -> bool {
    let word = word.trim_matches(is_emphasis);
    one_of("is was est était", word) || matches!(word, ":" | "=" | "->" | "=>" | "：")
}

/// Whether the value at `start..end` is a stopword (English or French), its emphasis
/// and closing punctuation aside (`__required__.`).
fn is_tail_stopword(text: &str, start: usize, end: usize) -> bool {
    let word = value_word(&text[start..end]).trim_matches(is_emphasis);
    let english = || {
        PROSE_STOPWORDS
            .iter()
            .any(|stop| stop.eq_ignore_ascii_case(word))
    };
    english() || one_of(FRENCH_STOPWORDS, word)
}

/// The value after a tail key's link, from `at`: after `set to` or `changed to` it must
/// look like a secret, as on main; else after one optional filler (`is now`, `est
/// maintenant`) it is the next word that is no stopword; else a word ending in `:`
/// within the qualifier caps brings a value that looks like a secret (`is the same as
/// before: …`).
fn tail_value(text: &str, at: usize, stop: usize) -> Option<SecretValue> {
    let next = next_word(text, at, stop, MAX_TERMINATOR_WORD)?;
    let word = &text[next.0..next.1];
    if one_of("set changed reset updated switched", word) {
        return set_to_value(text, at, stop, Need::Any);
    }
    let filler = one_of(FILLERS, word) || one_of(FRENCH_FILLERS, word);
    let from = if filler { next.1 } else { at };
    let (value, _) = phrase_value(text, from, stop, Need::Any, false);
    if let Some(value) = value.filter(|value| !is_tail_stopword(text, value.start, value.end)) {
        return Some(value);
    }
    let mut from = at;
    // `is the same as before: …`
    for _ in 0..MAX_QUALIFIER_WORDS {
        let (start, end) = next_word(text, from, stop, MAX_TERMINATOR_WORD)?;
        from = end;
        if end - at > MAX_QUALIFIER_BYTES || text[start..end].contains(['.', ',', ';', '!', '?']) {
            return None;
        }
        if text[..end].ends_with(':') {
            return phrase_value(text, end, stop, Need::Any, true).0;
        }
    }
    None
}

/// The K-SECRET-TAIL-2 spans, one reading for every phrasing (`My **password** is …`,
/// `password is set to …`, `Mon mot-de-passe est …`): a tail key and its emphasis, an
/// optional qualifier opened by an English or French head (`for the portal`, `du
/// portail`), a link ([`is_tail_link`]), and the value ([`tail_value`]) with its clause
/// tail unless it is quoted. It runs apart from [`phrase_scan`] and only adds spans
/// (strict superset by construction). A key inside text already read is skipped, so the
/// scan stays linear.
fn key_tail_scan(text: &str, breaks: &Breaks) -> Vec<SecretValue> {
    let mut extra = Vec::new();
    let (mut reach, mut resume) = (0, 0);
    // Same byte offsets: only ASCII letters change.
    let lower = text.to_ascii_lowercase();
    for key in TAIL_KEY_RE.find_iter(&lower) {
        let inside = text[..key.start()].ends_with(char::is_alphanumeric)
            || text[key.end()..].starts_with(char::is_alphanumeric);
        if key.start() < resume || inside {
            continue;
        }
        let stop = breaks.break_from(key.end());
        let mut at = skip_emphasis(text, key.end());
        let mut linked = false;
        // The link may follow the full qualifier, so it is read as one word more.
        for index in 0..=MAX_QUALIFIER_WORDS {
            let Some((start, end)) = next_word(text, at, stop, MAX_TERMINATOR_WORD) else {
                break;
            };
            let word = &text[start..end];
            at = end;
            if is_tail_link(word) {
                linked = true;
                break;
            }
            let head = one_of(FRENCH_HEADS, word)
                || QUALIFIER_HEADS
                    .iter()
                    .any(|head| head.eq_ignore_ascii_case(word));
            if (index == 0 && !head)
                || word.contains(['.', ',', ';', '!', '?', ':'])
                || end - key.end() > MAX_QUALIFIER_BYTES
            {
                break;
            }
        }
        resume = at;
        let value = linked.then(|| tail_value(text, at, stop)).flatten();
        resume = resume.max(value.map_or(0, |value| value.end));
        if let Some(value) = value {
            if !text[..value.start].ends_with(['"', '\'', '“', '‘', '«']) {
                push_tail(text, Some(&value), stop, &mut extra, &mut reach);
            }
            extra.push(value);
        }
    }
    // These spans are new to K-SECRET-TAIL-2: a long one is masked whole, never
    // refused, like `rest_value`'s whole-line remainder (`Mon mdp est `
    // + 1025 bytes was admitted on main and refused here). Every byte stays masked.
    for span in &mut extra {
        span.long = false;
    }
    extra
}

/// LABEL-VALUE-1 reads a value after its own prose links (`might be`, `,`, `set
/// to`) as [`key_tail_scan`] reads one after `is`: `None` for a stopword value at
/// `start..end`, else the end of its clause (`. , ; ! ?` or `stop`), never before `end`.
pub(crate) fn linked_clause_end(
    text: &str,
    start: usize,
    end: usize,
    stop: usize,
) -> Option<usize> {
    if is_tail_stopword(text, start, end) {
        return None;
    }
    let clause = text[start..stop]
        .split(['.', ',', ';', '!', '?'])
        .next()
        .unwrap_or("");
    Some(end.max(start + clause.trim_end().len()))
}

/// The phrase scan: its values, and the clause tails that only add to them
/// (K-SECRET-TAIL): after a password, key or code value, the rest of its clause
/// (`is correct horse battery staple`). The scan, its values and every cue it reads
/// stay exactly main's, so a tail can only add a mask (strict superset by
/// construction).
fn phrase_scan(text: &str, breaks: &Breaks) -> (Vec<SecretValue>, Vec<SecretValue>) {
    let mut values = Vec::new();
    let mut tails = Vec::new();
    // Where the last tail ended: a cue inside it shares its clause end, so its tail
    // adds nothing and is not read again (the scan stays linear).
    let mut tail_reach = 0;
    let mut resume = 0;
    for cue in PHRASE_CUE_RE.captures_iter(text) {
        let Some(whole) = cue.get(0) else {
            continue;
        };
        if whole.start() < resume {
            continue;
        }
        let (plural, phrase, code) = (cue.get(1).is_some(), cue.get(2).is_some(), cue.get(4));
        let need = match (cue.get(3), cue.get(5)) {
            (_, Some(_)) => Need::Token,
            (Some(_), None) => Need::Digit,
            (None, None) => Need::Any,
        };
        let stop = breaks.break_from(whole.end());
        let mut at = whole.end();
        let mut link = None;
        // The link may follow the full qualifier, so it is read as one word more.
        for index in 0..=MAX_QUALIFIER_WORDS {
            let Some((start, end)) = next_word(text, at, stop, MAX_TERMINATOR_WORD) else {
                break;
            };
            let word = &text[start..end];
            at = end;
            if index == 0 && is_label(word) {
                break;
            }
            if let Some(found) = link_of(word, plural) {
                link = (code.is_none() || index > 0).then_some(found);
                break;
            }
            // A qualifier is one clause: a word with sentence punctuation ends it.
            if index > 0 && word.contains(['.', ',', ';', '!', '?']) {
                break;
            }
            if index == 0
                && !QUALIFIER_HEADS
                    .iter()
                    .any(|head| head.eq_ignore_ascii_case(word))
            {
                // A value glued to a separator (`pwd=abc`) is the key-value rule's.
                if code.is_none() && word.starts_with(|ch: char| ch.is_alphanumeric()) {
                    let (value, read) = phrase_value(text, start, stop, need, true);
                    resume = resume.max(read);
                    values.extend(value);
                }
                break;
            }
            if end - whole.end() > MAX_QUALIFIER_BYTES {
                break;
            }
        }
        let Some(link) = link else {
            continue;
        };
        let adverb = next_word(text, at, stop, MAX_TERMINATOR_WORD)
            .filter(|&(start, end)| one_of(FILLERS, &text[start..end]));
        at = adverb.map_or(at, |(_, end)| end);
        let (mut value, mut read) = phrase_value(text, at, stop, need, false);
        // A passphrase runs to the end of its clause (`is correct horse battery staple`).
        let quoted = |start: usize| text[..start].ends_with(['"', '\'', '“', '‘', '«']);
        if let Some(value) = value
            .as_mut()
            .filter(|value| phrase && !quoted(value.start))
        {
            let mut limit = stop.min(value.start + MAX_PHRASE_QUOTE_BYTES);
            while !text.is_char_boundary(limit) {
                limit -= 1;
            }
            let clause = text[value.start..limit]
                .split(['.', ',', ';', '!', '?'])
                .next();
            value.end = value
                .end
                .max(value.start + clause.unwrap_or("").trim_end().len());
            read = read.max(value.end);
        }
        let tail_cue = !phrase && need == Need::Any && !plural;
        if tail_cue && !value.as_ref().is_some_and(|value| quoted(value.start)) {
            push_tail(text, value.as_ref(), stop, &mut tails, &mut tail_reach);
        }
        resume = resume.max(read);
        if value.is_some() || link == Link::Separator {
            let listed = plural && value.is_some();
            values.extend(value);
            // A list after `passwords`: each next value that looks like a secret, after
            // `and` or a comma.
            let and_at = |from: usize| {
                next_word(text, from, stop, MAX_TERMINATOR_WORD)
                    .filter(|&(start, end)| text[start..end].eq_ignore_ascii_case("and"))
            };
            // Set once the list went on past a closing quote, which main did not read:
            // those items never move `resume`, so every cue main read is still read.
            let mut past_quote = false;
            for _ in 1..if listed { MAX_LIST_VALUES } else { 1 } {
                let mut and = and_at(read);
                if and.is_none() && !text[..read].ends_with(',') {
                    // A quoted item ends at its closing quote; the list goes on after
                    // it (`are "A1xx" and "B2yy"`, K-PUBLIC-MISSES).
                    let close = text[read..]
                        .chars()
                        .next()
                        .filter(|ch| "\"'”’»".contains(*ch));
                    let Some(close) = close else {
                        break;
                    };
                    read += close.len_utf8();
                    past_quote = true;
                    // A comma after the closing quote separates the items too
                    // (`are 'A1xx', 'B2yy'`, pre-review of #129).
                    if text[read..].starts_with(',') {
                        read += 1;
                    }
                    and = and_at(read);
                    if and.is_none() && !text[..read].ends_with(',') {
                        break;
                    }
                }
                let next = and.map_or(read, |(_, end)| end);
                let (Some(item), after) = phrase_value(text, next, stop, need, true) else {
                    break;
                };
                values.push(item);
                read = after;
                if !past_quote {
                    resume = resume.max(after);
                }
            }
            continue;
        }
        // `is set to 4521`, `was changed to 4521` (K-PUBLIC-MISSES): read on its own,
        // so the scan below runs as on main.
        values.extend(set_to_value(text, at, stop, need));
        let filler = at;
        for _ in 0..MAX_QUALIFIER_WORDS {
            let Some((_, end)) = next_word(text, at, stop, MAX_TERMINATOR_WORD) else {
                break;
            };
            at = end;
            if end - filler > MAX_QUALIFIER_BYTES {
                break;
            }
            if text[..end].ends_with(':') {
                let (value, read) = phrase_value(text, at, stop, need, true);
                resume = resume.max(read);
                // `is the same as before: Sunflower#88 horse battery staple` (seal r1
                // of #143): the clause tail follows this value too.
                if !phrase && need == Need::Any && !plural {
                    push_tail(text, value.as_ref(), stop, &mut tails, &mut tail_reach);
                }
                values.extend(value);
                break;
            }
        }
    }
    (values, tails)
}

/// The value after `set to` or `changed to` (also `reset`, `updated`, `switched`), from
/// `at`: it must look like a secret and meet `need`.
fn set_to_value(text: &str, at: usize, stop: usize, need: Need) -> Option<SecretValue> {
    let (start, end) = next_word(text, at, stop, MAX_TERMINATOR_WORD)?;
    if !one_of("set changed reset updated switched", &text[start..end]) {
        return None;
    }
    let (start, end) = next_word(text, end, stop, MAX_TERMINATOR_WORD)?;
    if !text[start..end].eq_ignore_ascii_case("to") {
        return None;
    }
    phrase_value(text, end, stop, need, true).0
}

/// A MySQL command word, or a `-u` or `--user` flag, which makes a glued `-p` a
/// password on the same line (K13). The command word is case-insensitive; the
/// flags are not.
static MYSQL_COMMAND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:\bmysql(?:dump)?\b|\bmariadb\b)|(?:^|\s)(?:-u|--user)")
        .expect("mysql command shape compiles")
});

/// A `-p` flag glued to its value, with no space, as `mysql -pSECRET` takes it.
static MYSQL_FLAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)-p(\S+)").expect("mysql flag shape compiles"));

/// The MySQL-style values (K13): a glued `-p` value on a line that names a MySQL or
/// MariaDB command or a `-u` or `--user` flag. Each line is read on its own.
fn mysql_values(text: &str) -> Vec<SecretValue> {
    let mut values = Vec::new();
    for (line_start, line_stop) in line_spans(text) {
        let line = &text[line_start..line_stop];
        if !line.contains("-p") || !MYSQL_COMMAND_RE.is_match(line) {
            continue;
        }
        for captures in MYSQL_FLAG_RE.captures_iter(line) {
            let Some(value) = captures.get(1) else {
                continue;
            };
            let word = value_word(value.as_str());
            if is_value_word(word) {
                let start = line_start + value.start();
                values.push(SecretValue {
                    start,
                    end: start + word.len(),
                    long: word.len() > MAX_VALUE_BYTES,
                });
            }
        }
    }
    values
}

/// Every secret-class value in `text`: the key-value pairs, the k8s pairs, the XML
/// elements and the command-line flags. The prose rule and the MySQL flag add the
/// values that do not overlap a name-assigned value, which wins on overlap (K10).
fn secret_values(text: &str) -> Vec<SecretValue> {
    let mut values = key_values(text);
    values.extend(k8s_values(text));
    values.extend(xml_values(text));
    values.extend(cli_values(text));
    let mut assigned = values.clone();
    assigned.sort_unstable_by_key(|value| value.start);
    // The furthest end of the values up to each index: a value overlaps one of
    // them exactly when the furthest end before its own end passes its start.
    let mut reach = Vec::with_capacity(assigned.len());
    let mut furthest = 0;
    for value in &assigned {
        furthest = furthest.max(value.end);
        reach.push(furthest);
    }
    let (prose, tails) = prose_values(text);
    for value in prose.into_iter().chain(mysql_values(text)) {
        let before = assigned.partition_point(|kept| kept.start < value.end);
        let overlaps = before > 0 && reach[before - 1] > value.start;
        if !overlaps {
            values.push(value);
        }
    }
    // Clause tails are added after the K10 overlap rule, never filtered by it: a tail
    // only widens what is masked (K-SECRET-TAIL).
    values.extend(tails);
    values
}

/// Whether a secret-class value in `text` is longer than the gate reads. The gate
/// refuses such text (fail closed): a value is never masked in part.
pub fn value_too_long(text: &str) -> bool {
    let view = KeyView::for_text(text);
    let haystack = view.as_ref().map_or(text, |view| view.text.as_str());
    secret_values(haystack).iter().any(|value| value.long)
}

/// The userinfo of a URL, `scheme://user:password@`, for any host. The user may be
/// empty (`redis://:password@host`). The password is the secret; the user is one
/// too when it is not empty.
static DSN_USERINFO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.\-]*://([^\s/@:"'<>]*):([^\s/@"'<>]+)@"#)
        .expect("DSN userinfo shape compiles")
});

/// The value of an `Authorization:` header with a Bearer or Basic credential.
static AUTHORIZATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)Authorization:\s*(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=\-]{8,})")
        .expect("authorization shape compiles")
});

/// A PEM private-key block (OPENSSH, RSA, EC, PGP and generic), from its header to
/// its footer. Without a footer the block runs to the end of the text: a header
/// with no footer is still a key, so it fails toward masking.
static PEM_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----|\z)",
    )
    .expect("PEM block shape compiles")
});

/// A PuTTY private key file (`.ppk`), from its header to its MAC line.
static PUTTY_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"PuTTY-User-Key-File-\d: [^\n]*\n[\s\S]*?(?:Private-MAC: [0-9a-f]+|\z)")
        .expect("PuTTY key shape compiles")
});

/// A PEM body with no header: a line of 64 characters that opens with `MII`, and
/// two or more lines of 64 characters after it (the base64 of a DER key).
static HEADERLESS_PEM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^MII[A-Za-z0-9+/]{61}(?:\r?\n[A-Za-z0-9+/]{64}){2,}(?:\r?\n[A-Za-z0-9+/]{1,64}={0,2})?")
        .expect("headerless PEM shape compiles")
});

/// Whether a character belongs to a secret value (an AWS key or a token).
fn is_value_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '/' | '+' | '=' | '_' | '-')
}

static SHAPES_RE: LazyLock<Vec<(Regex, usize)>> = LazyLock::new(|| {
    SHAPES
        .iter()
        .map(|(shape, min_len)| {
            (
                Regex::new(shape).expect("secret key shape compiles"),
                *min_len,
            )
        })
        .collect()
});

/// The cue of a short numeric code (K-PII-TRACE-GAPS-2): a PIN, an OTP or a
/// passcode (group 1), whose code needs four digits, or the word `code`, six.
static CODE_CUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:(pin|otp|passcode|",
        r"codes?[ \t]+de[ \t]+(?:v[ée]rification|s[ée]curit[ée]))|codes?)\b"
    ))
    .expect("code cue compiles")
});

/// Words before a bare `code` that make it public (`zip code 75001`).
const PUBLIC_CODE_HEADS: &str =
    "zip postal post area country dialing dialling status error exit http promo discount product";
/// Words that may stand between a cue and its code (`code is`, `PIN: your`).
const CODE_FILLERS: &str =
    "is was are be will est sera your my the votre ton mon le la de du number";
/// What may follow a number to make it an amount.
const CURRENCIES: &str = "€ $ £ ¥ % eur usd gbp chf cny rmb euro euros dollar dollars yuan";
/// Bytes read for the gap before a code, for a head word, and the most digits.
const MAX_CODE_GAP: usize = 40;
const MAX_HEAD_BYTES: usize = 24;
const MAX_CODE_DIGITS: usize = 10;

/// A PIN, one-time or verification code written after its cue in groups:
/// `PIN 1234  5678`, `OTP 12 . 34 . 56`, `code: 803-143-301`. The groups are
/// joined by up to three spaces or line breaks on each side of an optional
/// dot or dash, and masked whole. A decimal, a date, an amount or a number
/// that runs on stays clear, and a date or a decimal ends the search rather
/// than falling back to its leading groups; when only the joined value is an
/// amount, its first groups are still a code (`OTP 1234  56 USD` masks
/// `1234`).
#[derive(Clone, Copy, Debug, Default)]
pub struct CuedCodeRecognizer;

impl Recognizer for CuedCodeRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Secret]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        CODE_CUE_RE
            .captures_iter(text)
            .filter_map(|cue| {
                let (whole, strong) = (cue.get(0)?, cue.get(1).is_some());
                let from = text.ceil_char_boundary(whole.start().saturating_sub(MAX_HEAD_BYTES));
                let head = text[from..whole.start()].trim_end_matches([' ', '\t', '-']);
                let head = head.rsplit(|ch: char| !ch.is_alphanumeric()).next();
                if !strong && one_of(PUBLIC_CODE_HEADS, head.unwrap_or("")) {
                    return None;
                }
                let start = code_start(text, whole.end())?;
                let end = code_end(text, start, if strong { 4 } else { 6 })?;
                Some(Span::new(
                    EntityKind::Secret,
                    start,
                    end,
                    SCORE,
                    self.name(),
                ))
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "cued_code"
    }
}

/// Where the code after a cue ending at `from` starts: punctuation and filler
/// words only, within [`MAX_CODE_GAP`] bytes.
fn code_start(text: &str, from: usize) -> Option<usize> {
    let mut at = from;
    while at < from + MAX_CODE_GAP {
        let ch = text[at..].chars().next()?;
        if ch.is_ascii_digit() {
            return Some(at);
        }
        if ch.is_alphabetic() {
            let len: usize = text[at..]
                .chars()
                .take_while(|c| c.is_alphabetic())
                .map(char::len_utf8)
                .sum();
            if !one_of(CODE_FILLERS, &text[at..at + len]) {
                return None;
            }
            at += len;
        } else if " \t\r\n:：=#-–—>*\"'“”‘’«»([".contains(ch) {
            at += ch.len_utf8();
        } else {
            return None;
        }
    }
    None
}

/// The bytes of the separator at `at` between two groups: up to three spaces
/// or line breaks, an optional `.` or `-`, up to three more; 0 for none.
fn code_separator(bytes: &[u8], at: usize) -> usize {
    let space = |from: usize| {
        bytes[from.min(bytes.len())..]
            .iter()
            .take(4)
            .take_while(|b| b.is_ascii_whitespace())
            .count()
    };
    let before = space(at);
    let mark = usize::from(matches!(bytes.get(at + before), Some(b'.' | b'-')));
    let after = if mark == 1 { space(at + before + 1) } else { 0 };
    if before > 3 || after > 3 {
        return 0;
    }
    before + mark + after
}

/// The end of the code starting at `at`: the most groups, `min` to
/// [`MAX_CODE_DIGITS`] digits, that are no decimal, date or amount and that no
/// letter or further number touches.
///
/// A value that parses as a date or as a decimal ends the search: no shorter
/// prefix of `2026-10-21` or of `1234.50` is a code either, and retrying would
/// mask `2026-` and `1234`. An amount is the one shape that does fall back to
/// the groups before it (`OTP 1234  56 USD` masks `1234`).
fn code_end(text: &str, at: usize, min: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let (mut groups, mut joints) = (Vec::new(), Vec::new());
    let (mut start, mut digits) = (at, 0);
    loop {
        let run = bytes[start..]
            .iter()
            .take(MAX_CODE_DIGITS + 1)
            .take_while(|b| b.is_ascii_digit())
            .count();
        digits += run;
        if digits > MAX_CODE_DIGITS {
            return None;
        }
        groups.push((start, start + run, digits));
        let separator = code_separator(bytes, start + run);
        if separator == 0
            || !bytes
                .get(start + run + separator)
                .is_some_and(u8::is_ascii_digit)
        {
            break;
        }
        joints.push(&text[start + run..start + run + separator]);
        start += run + separator;
    }
    let decimal = |count: usize| count == 2 && joints[0] == "." && groups[1].1 - groups[1].0 <= 2;
    // The whole run of groups read: three groups that are a date, or two that
    // are a decimal, and the value around them is not a code.
    if decimal(groups.len()) || (groups.len() == 3 && is_date(text, &groups, &joints)) {
        return None;
    }
    (1..=groups.len()).rev().find_map(|count| {
        let (_, end, digits) = groups[count - 1];
        let rest = &text[end..];
        let runs_on = rest.starts_with(char::is_alphanumeric)
            || rest.len() > 1
                && rest.starts_with([',', '/', ':'])
                && rest.as_bytes()[1].is_ascii_digit();
        let unit = rest.trim_start_matches([' ', '\u{a0}']);
        let amount = CURRENCIES.split(' ').any(|currency| {
            unit.get(..currency.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(currency))
                && !unit[currency.len()..].starts_with(|ch: char| ch.is_alphabetic())
        });
        (digits >= min && !decimal(count) && !runs_on && !amount).then_some(end)
    })
}

/// Whether three groups joined by the same `-` or `.` are a date.
fn is_date(text: &str, groups: &[(usize, usize, usize)], joints: &[&str]) -> bool {
    let field = |index: usize| {
        let (start, end, _) = groups[index];
        (end - start, text[start..end].parse::<u32>().unwrap_or(0))
    };
    let [(l0, v0), (l1, v1), (l2, v2)] = [0, 1, 2].map(field);
    let day_month = |x: u32, y: u32| (1..=31).contains(&x) && (1..=12).contains(&y);
    let either = |x, y| day_month(x, y) || day_month(y, x);
    joints[0] == joints[1]
        && matches!(joints[0], "-" | ".")
        && l1 <= 2
        && (l0 == 4 && l2 <= 2 && either(v1, v2) || l2 == 4 && l0 <= 2 && either(v0, v1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<&str> {
        let mut spans: Vec<_> = SecretRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| (span.start, span.end))
            .collect();
        // `link_scan` may repeat a span of main's: the same bytes, one hit.
        spans.sort_unstable();
        spans.dedup();
        spans
            .into_iter()
            .map(|(start, end)| &text[start..end])
            .collect()
    }

    #[test]
    fn a_key_is_one_span_with_its_prefix() {
        let key = concat!("sk-proj-", "FAKEKEY0123456789abcdefGHIJKL");
        assert_eq!(hits(&format!("key {key} end")), vec![key]);
    }

    #[test]
    fn a_lower_case_aws_key_is_masked_and_akia_words_are_not() {
        let key = concat!("akia", "iosfodnn7example");
        assert_eq!(hits(&format!("key {key}.")), vec![key]);
        // SECRET-1: a word glued after the key no longer hides it; SECRET-2:
        // the glued suffix goes with it.
        assert_eq!(hits(&format!("{key}s")), vec![format!("{key}s")]);
        for text in [format!("x{key}"), key[..19].to_string()] {
            assert!(hits(&text).is_empty(), "{text} is masked");
        }
    }

    #[test]
    fn a_short_sk_word_is_not_a_key() {
        assert!(hits("the sk-learn package").is_empty());
    }

    #[test]
    fn a_key_glued_to_a_word_is_still_a_key() {
        let key = concat!("sk-", "aB3dE6gH9jK2mN5pQ8sT1vW4xY7zA0cD3fG6hJ9kL2mN5pQ8");
        assert_eq!(hits(&format!("task-{key}")), vec![key]);
        assert_eq!(hits(&format!("我的{key}")), vec![key]);
    }

    #[test]
    fn glued_key_masks_only_key_and_leaves_identifier_suffix_clear() {
        let key = concat!("sk-", "aB3dE6gH9jK2mN5pQ8sT1vW4xY7zA0cD3fG6hJ9kL2mN5pQ8");
        for suffix in [" next", "_build_id", "-release_notes", ".env"] {
            let text = format!("task-{key}{suffix}");
            assert_eq!(hits(&text), vec![key], "{suffix}");
        }
    }

    #[test]
    fn long_camel_and_kebab_identifiers_are_not_glued_keys() {
        let long = "calculateTotalAmountForUserAccountBalanceInEuros2024";
        assert!(plainly_words(&format!("sk-{long}")));
        for prefix in ["desk-", "mask-", "whisk-", "ask-"] {
            let text = format!("{prefix}{long}");
            assert!(hits(&text).is_empty(), "{text}");
        }
        for text in [
            concat!(
                "ta",
                "sk-",
                "calculateTotalAmountForUserAccountBalanceInEuros2024"
            ),
            concat!(
                "ri",
                "sk-",
                "assessmentForQuarterlyReportGenerationAndReview2025"
            ),
            concat!(
                "ri",
                "sk-",
                "assessment-for-quarterly-report-generation-and-review-2025"
            ),
            "desk-",
            "mask-",
            "whisk-",
            "ask-",
            "task-calculate_total_amount_for_user_account_balance_in_euros_2024",
            "lib/kernel_privacy/src/recognizers/secrets.rs",
        ] {
            assert_eq!(hits(text), Vec::<&str>::new(), "{text}");
        }
    }

    #[test]
    fn a_project_key_with_suffix_stops_at_the_64_byte_body() {
        let key = format!("sk-proj-{}a", "aB3".repeat(21));
        assert_eq!(key.len(), 72);
        for suffix in ["", ".", "x", "7", "_", "-"] {
            assert_eq!(
                hits(&format!("n{key}{suffix}")),
                vec![key.as_str()],
                "{suffix}"
            );
        }
    }

    #[test]
    fn a_wrapped_key_joins_its_continuation_run() {
        assert_eq!(
            hits("sk-proj-FAKEKEY0123\nFAKEKEY456 end"),
            vec!["sk-proj-FAKEKEY0123\nFAKEKEY456"]
        );
    }

    #[test]
    fn a_line_that_does_not_open_with_key_alphabet_ends_the_key() {
        assert_eq!(
            hits("sk-proj-FAKEKEY0123456789\n: the rest"),
            vec!["sk-proj-FAKEKEY0123456789"]
        );
    }

    #[test]
    fn the_join_stops_after_the_line_cap() {
        let text = "sk-a\n".repeat(10_000);
        let spans = SecretRecognizer::new().analyze(&text);
        assert!(spans
            .iter()
            .all(|span| span.end - span.start <= MAX_WRAP_BYTES + 5));
    }

    #[test]
    fn a_key_at_a_line_end_does_not_join_the_next_key() {
        // A config file has one key per line: the next line's `NAME=` or `NAME:`
        // is a key, not a wrapped continuation of the token above it.
        assert_eq!(
            hits("sntrys_FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz\nLOG_LEVEL=info"),
            vec!["sntrys_FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz"]
        );
        assert_eq!(
            hits("sk-proj-FAKEKEY0123456789\nendpoint: x"),
            vec!["sk-proj-FAKEKEY0123456789"]
        );
        // Base64 padding is not a separator: a wrapped `AB==` still joins.
        assert_eq!(
            hits("sk-proj-FAKEKEY0123456789\nAB=="),
            vec!["sk-proj-FAKEKEY0123456789\nAB"]
        );
    }

    #[test]
    fn a_multi_word_password_is_masked_to_its_clause_end() {
        let masked = |text: &str| {
            let mut kept: Vec<(usize, usize)> = SecretRecognizer::new()
                .analyze(text)
                .into_iter()
                .map(|span| (span.start, span.end))
                .collect();
            kept.sort_unstable();
            text.char_indices()
                .filter(|&(at, _)| !kept.iter().any(|&(start, end)| start <= at && at < end))
                .map(|(_, ch)| ch)
                .collect::<String>()
        };
        for (text, clear) in [
            (
                "My password is correct horse battery staple",
                "My password is ",
            ),
            (
                "Password for the portal is Tr0ub4dor and3 more words. Thanks",
                "Password for the portal is ",
            ),
            // Seal r1 of #142: a key-value later on the line, a long tail.
            (
                "My password is correct horse battery staple token=Tail9Token",
                "My password is ",
            ),
            // Seal r2 of #142: main's later values all stay masked.
            (
                "token=\"password is correct password\" is Outside9Secret",
                "",
            ),
            ("token=\"password is correct\" pin is 4821", ""),
        ] {
            let out = masked(text);
            for word in [
                "horse",
                "staple",
                "Tail9Token",
                "more",
                "Outside9Secret",
                "4821",
            ] {
                assert!(
                    !out.contains(word),
                    "{word} left clear in {text:?}: {out:?}"
                );
            }
            if !clear.is_empty() {
                assert_eq!(out, clear, "{text}");
            }
        }
        let colon = "password is the same as before: Sunflower#88 horse battery staple";
        assert!(!masked(colon).contains("horse"), "{}", masked(colon));
        let colon_long = format!("{colon} {}TAIL", "word ".repeat(300));
        assert!(value_too_long(&colon_long));
        let long = format!("password is {}TAIL", "word ".repeat(26));
        assert!(!masked(&long).contains("TAIL"));
        assert!(value_too_long(&format!(
            "password is correct pin is A1{}",
            "x".repeat(1024)
        )));
        // K-SECRET-TAIL-4 over-mask: a value runs to its paragraph end.
        assert_eq!(hits("Your password is required"), vec!["required"]);
    }

    /// The text with every masked character left out.
    fn clear_of(text: &str) -> String {
        let spans = SecretRecognizer::new().analyze(text);
        text.char_indices()
            .filter(|&(at, _)| !spans.iter().any(|span| span.start <= at && at < span.end))
            .map(|(_, ch)| ch)
            .collect()
    }

    /// Main's spans and `value_too_long` (2e85caf7) for the differential corpus: the
    /// secrets tests' inputs, the K-SECRET-TAIL-2 inputs and 20 sentences with no
    /// secret. Main's over-masks (`before`, `rules`, `again`) are kept as they are.
    /// A text, main's spans of it, and main's `value_too_long`.
    type Pinned = (&'static str, &'static [(usize, usize)], bool);

    #[rustfmt::skip]
    const MAIN_SPANS: &[Pinned] = &[
        ("My password is correct horse battery staple", &[(15, 22), (22, 43)], false),
        ("Password for the portal is Tr0ub4dor and3 more words. Thanks", &[(27, 36), (36, 52)], false),
        ("My password is correct horse battery staple token=Tail9Token", &[(15, 22), (22, 60), (50, 60)], false),
        ("token=\"password is correct password\" is Outside9Secret", &[(6, 36), (26, 54), (40, 54)], false),
        ("token=\"password is correct\" pin is 4821", &[(6, 27), (26, 39), (35, 39)], false),
        ("password is the same as before: Sunflower#88 horse battery staple", &[(32, 44), (44, 65)], false),
        ("Your password is required", &[], false),
        ("my password is Tr0ubProse42", &[(15, 27)], false),
        ("mysql -pTr0ubCliP42", &[(8, 19)], false),
        ("api key: Q7vL2mX9pR4tY8wZ1nB6cD3fGhJkLmNp", &[(9, 41)], false),
        ("the wifi password is Xk9mP2q", &[(21, 28)], false),
        ("passwd Xk9mP2q", &[(7, 14)], false),
        ("**password**: Zq7Lm2Xr", &[(14, 22)], false),
        ("`password` is Zq7Lm2Xr", &[(14, 22)], false),
        ("\"password\" is Zq7Lm2Xr", &[(14, 22)], false),
        ("'api key': Zq7Lm2Xr", &[(11, 19)], false),
        ("__passwd__ Zq7Lm2Xr", &[(11, 19)], false),
        ("`token`: Zq7Lm2Xr", &[(9, 17)], false),
        ("**api_key**: Zq7Lm2Xr", &[(13, 21)], false),
        ("**Secret key:** Zq7Lm2Xr", &[(16, 24)], false),
        ("`token` is Zq7Lm2Xr", &[(11, 19)], false),
        ("“password” is Zq7Lm2Xr", &[(18, 26)], false),
        ("my “password” is Zq7Lm2Xr", &[(21, 29)], false),
        ("«password» is Zq7Lm2Xr", &[(16, 24)], false),
        ("password is Zq7*****", &[(12, 20)], false),
        ("my password is hunter2}}}", &[(15, 25)], false),
        ("__token__ is Zq7Lm2Xr", &[(13, 21)], false),
        ("`clientSecret` is Zq7Lm2Xr", &[(18, 26)], false),
        ("the `GITHUB_TOKEN` is Zq7Lm2Xr", &[(22, 30)], false),
        ("the `status` is Zq7Lm2Xr", &[], false),
        ("the password manager", &[], false),
        ("reset the password for Camille", &[], false),
        ("the api key field", &[], false),
        ("the `token` field", &[], false),
        ("pwd", &[], false),
        ("ssh -pTr0ubCliP42 host", &[], false),
        ("My **password** is correct horse battery staple", &[(19, 26)], false),
        ("My password is set to Tr0ub4dor horse battery staple", &[(22, 31)], false),
        ("Mon mot de passe est correct horse battery staple", &[], false),
        ("My password is set.", &[], false),
        ("password: **hunter2**", &[(10, 21)], false),
        ("mot de passe : correct horse battery staple", &[(15, 43)], false),
        ("Mot de passe : Tr0ub4dor", &[(15, 24)], false),
        ("mdp: Tr0ub4dor horse battery staple", &[(5, 35)], false),
        ("Mon mdp est Tr0ub4dor horse battery staple", &[], false),
        ("My `password` is correct horse battery staple, thanks", &[(17, 24)], false),
        ("**password** is Zq7Lm2Xr", &[(16, 24)], false),
        ("My password was changed to Tr0ub4dor horse battery staple. Bye", &[(27, 36)], false),
        ("password is set to \"Tr0ub4dor horse\" ok", &[(20, 35)], false),
        ("Le mot de passe du portail est correct horse battery staple", &[], false),
        ("**password** is pin is 4821", &[(23, 27)], false),
        ("My __password__ is correct horse battery staple", &[(19, 26)], false),
        ("My **password** is set to Tr0ub4dor horse battery staple", &[], false),
        ("Mon mot-de-passe est Tr0ub4dor horse battery staple", &[], false),
        ("Mon **mot de passe** est Tr0ub4dor horse battery staple", &[], false),
        ("The password policy is set to strict mode for the team.", &[], false),
        ("Mon mot de passe est oublié.", &[], false),
        ("Le mot de passe est trop court.", &[], false),
        ("Mon mot de passe est incorrect, merci de le changer.", &[], false),
        ("Please reset your password before Monday.", &[(27, 33)], false),
        ("The password is required to log in.", &[], false),
        ("We changed the password rules last week.", &[(24, 29)], false),
        ("Your password must have eight characters.", &[], false),
        ("I forgot my password again, sorry.", &[(21, 26)], false),
        ("The **password** field is empty.", &[], false),
        ("The password reset link expired.", &[], false),
        ("Password strength: Strong", &[(9, 18)], false),
        ("The api key field is empty.", &[], false),
        ("Mot de passe oublié ?", &[], false),
        ("Le mot de passe a été changé hier.", &[], false),
        ("Où est mon mot de passe ?", &[], false),
        ("The pass to the museum is on the table.", &[], false),
        ("Our team code review is on Friday.", &[], false),
        ("The token of thanks was a card.", &[], false),
        ("Merci pour le mot de passe, il marche.", &[], false),
    ];

    #[test]
    fn every_span_of_main_is_still_produced() {
        for &(text, main, too_long) in MAIN_SPANS {
            let new: Vec<(usize, usize)> = SecretRecognizer::new()
                .analyze(text)
                .into_iter()
                .map(|span| (span.start, span.end))
                .collect();
            for span in main {
                assert!(new.contains(span), "{text}: lost {span:?}, now {new:?}");
            }
            assert_eq!(value_too_long(text), too_long, "{text}");
        }
        // The sentences with no secret gain no span (the last 20 rows).
        for &(text, main, _) in &MAIN_SPANS[MAIN_SPANS.len() - 20..] {
            let mut new: Vec<(usize, usize)> = SecretRecognizer::new()
                .analyze(text)
                .into_iter()
                .map(|span| (span.start, span.end))
                .collect();
            new.sort_unstable();
            let over = OVER_MASKS.iter().find(|row| row.0 == text);
            assert_eq!(new, over.map_or(main, |row| row.1), "{text}");
        }
    }

    /// K-SECRET-TAIL-4 over-masks: the no-secret rows that now mask the words
    /// after their link, with main's spans kept.
    #[rustfmt::skip]
    const OVER_MASKS: &[(&str, &[(usize, usize)])] = &[
        ("Mon mot de passe est oublié.", &[(21, 29)]),
        ("Le mot de passe est trop court.", &[(20, 31)]),
        ("Mon mot de passe est incorrect, merci de le changer.", &[(21, 52)]),
        ("The password is required to log in.", &[(16, 35)]),
        ("Password strength: Strong", &[(9, 18), (19, 25)]),
    ];

    /// A multi-word password and what is masked of it: main masked only its first word,
    /// or (French) nothing (seals r1 of #142 and #148).
    #[rustfmt::skip]
    const DECORATED_VALUES: &[(&str, &str)] = &[
        ("My **password** is correct horse battery staple", "correct horse battery staple"),
        ("My password is set to Tr0ub4dor horse battery staple", "Tr0ub4dor horse battery staple"),
        ("Mon mot de passe est correct horse battery staple", "correct horse battery staple"),
        ("My `password` is correct horse battery staple, thanks", "correct horse battery staple"),
        ("My password was changed to Tr0ub4dor horse battery staple. Bye", "Tr0ub4dor horse battery staple"),
        ("Le mot de passe du portail est correct horse battery staple", "correct horse battery staple"),
        ("mot de passe : correct horse battery staple", "correct horse battery staple"),
        // The asterisks are masked with the value, as main masks them.
        ("password: **hunter2**", "**hunter2**"),
        // A quoted value ends at its quote, as on main.
        ("password is set to \"Tr0ub4dor horse\" ok", "Tr0ub4dor horse"),
        ("My __password__ is correct horse battery staple", "correct horse battery staple"),
        ("My **password** is set to Tr0ub4dor horse battery staple", "Tr0ub4dor horse battery staple"),
        ("Mon mot-de-passe est Tr0ub4dor horse battery staple", "Tr0ub4dor horse battery staple"),
        ("Mon **mot de passe** est Tr0ub4dor horse battery staple", "Tr0ub4dor horse battery staple"),
        // A stopword glued to more is a value.
        ("Mon mot de passe est trop2024!", "trop2024!"),
        ("My **password** is the same as before: Sunflower#88 horse", "Sunflower#88 horse"),
    ];

    #[test]
    fn every_key_decoration_and_link_masks_the_whole_value() {
        let mut texts: Vec<(String, &str)> = DECORATED_VALUES
            .iter()
            .map(|&(text, value)| (text.to_owned(), value))
            .collect();
        let english = ["password", "Password", "PASSWORD", "pwd"].map(|key| (key, "My", true));
        let french =
            ["mot de passe", "mot-de-passe", "MOT DE PASSE", "mdp"].map(|key| (key, "Mon", false));
        for (key, lead, is_english) in english.into_iter().chain(french) {
            let links: &[&str] = if is_english {
                &[" is", " is set to", " was set to", " is now", ":"]
            } else {
                &[" est", " est maintenant", " :"]
            };
            for marks in ["", "**", "__", "`", "*"] {
                for link in links {
                    let text =
                        format!("{lead} {marks}{key}{marks}{link} Tr0ub4dor horse battery staple");
                    texts.push((text, "Tr0ub4dor horse battery staple"));
                }
            }
        }
        assert_eq!(texts.len(), DECORATED_VALUES.len() + 160);
        let wrong: Vec<_> = texts
            .iter()
            // K-SECRET-TAIL-4: the value runs to the text end, so what stays clear is
            // a head of the text that ends before the value.
            .filter(|(text, value)| {
                let clear = clear_of(text);
                !text.starts_with(&clear) || text.find(value).is_none_or(|at| clear.len() > at)
            })
            .map(|(text, _)| (text, clear_of(text)))
            .collect();
        assert!(
            wrong.is_empty(),
            "{} of {} leak: {wrong:#?}",
            wrong.len(),
            texts.len()
        );
        // Decorated sentences with no secret keep their pinned spans.
        for &(text, pinned) in DECORATED_NO_SECRET {
            let mut new: Vec<(usize, usize)> = SecretRecognizer::new()
                .analyze(text)
                .iter()
                .map(|span| (span.start, span.end))
                .collect();
            new.sort_unstable();
            assert_eq!(new, pinned, "{text}");
        }
        // A long value or tail of this reading is masked whole, never refused:
        // main admitted these texts, and no byte of the secret is left clear.
        for long in [
            format!("My **password** is correct {}TAIL", "word ".repeat(300)),
            format!("Mon mdp est {}", "a".repeat(1025)),
        ] {
            assert!(!value_too_long(&long), "{long}");
            let start = long.find(" is ").map_or(12, |at| at + 4);
            let masked: usize = hits(&long).iter().map(|hit| hit.len()).sum();
            assert!(masked >= long.len() - start, "{long}");
        }
    }

    /// Accepted over-masks: after `mot de passe est`, any word that is not
    /// a stopword is read as the value, so a sentence about a password loses a few
    /// words to a mask. Secrets fail closed; these texts still pass the gate.
    #[test]
    fn a_french_sentence_about_a_password_is_over_masked_but_admitted() {
        for (text, pinned) in [
            (
                "Mon mot de passe est facile à retenir.",
                vec![(21, 27), (21, 39), (27, 38)],
            ),
            (
                "Le mot de passe est difficile à mémoriser.",
                vec![(20, 29), (20, 44), (29, 43)],
            ),
            (
                "Le mot de passe est secret et personnel.",
                vec![(20, 26), (20, 40), (26, 39)],
            ),
            (
                "Le mdp est utilisé pour se connecter.",
                vec![(11, 19), (11, 38), (19, 37)],
            ),
        ] {
            let mut spans: Vec<(usize, usize)> = SecretRecognizer::new()
                .analyze(text)
                .iter()
                .map(|span| (span.start, span.end))
                .collect();
            spans.sort_unstable();
            assert_eq!(spans, pinned, "{text}");
            assert!(!value_too_long(text), "{text}");
        }
    }

    /// Decorated sentences with no secret and their spans; an over-mask says why.
    #[rustfmt::skip]
    const DECORATED_NO_SECRET: &[(&str, &[(usize, usize)])] = &[
        ("The **password** policy is strict.", &[]),
        ("Le **mot de passe** doit être changé.", &[]),
        // Main's over-mask: its key rule reads `__required__` as a value.
        ("Your password is __required__.", &[(17, 29), (17, 30)]),
        ("The `password` field is required.", &[]),
        // Main's over-mask, the same: `*incorrect*`.
        ("Your **password** is *incorrect*.", &[(21, 32), (21, 33)]),
        ("Le *mot-de-passe* est **obligatoire**.", &[(22, 38)]),
        // Main's over-mask: its key rule masks the word after `pwd`.
        ("The __pwd__ command prints the folder.", &[(12, 19)]),
        // Main's over-mask: `**Password reset**` is a decorated secret name.
        ("**Password reset** is done.", &[(22, 26)]),
        ("Mon `mdp` est ~~oublié~~.", &[(14, 26)]),
        ("The ~~password~~ hint is in the vault.", &[]),
        ("My password is set.", &[(15, 19)]),
        ("**password** is pin is 4821", &[(16, 27), (23, 27)]),
    ];

    #[test]
    #[rustfmt::skip]
    fn a_non_ascii_character_after_a_cue_never_splits_a_character() {
        let keys = ["password", "**password**", "mot de passe", "mdp", "password is set to"];
        let more = ["mot-de-passe est", "**password** is", "__pwd__:", "password is"];
        for key in keys.into_iter().chain(more) {
            for after in ["é", "😀", "密码", " é", " est é", " is 😀x", "é horse", " 😀😀😀😀 é. x", "\u{301}"] {
                let text = format!("{key}{after}{after} tail");
                for span in SecretRecognizer::new().analyze(&text) {
                    assert!(text.is_char_boundary(span.start) && text.is_char_boundary(span.end), "{text:?}: {span:?}");
                }
                let _ = value_too_long(&text);
            }
        }
    }

    #[test]
    fn a_prose_key_masks_the_next_word() {
        assert_eq!(hits("my password is Tr0ubProse42"), vec!["Tr0ubProse42"]);
        assert_eq!(hits("mysql -pTr0ubCliP42"), vec!["Tr0ubCliP42"]);
        assert_eq!(
            hits("api key: Q7vL2mX9pR4tY8wZ1nB6cD3fGhJkLmNp"),
            vec!["Q7vL2mX9pR4tY8wZ1nB6cD3fGhJkLmNp"]
        );
        assert_eq!(hits("the wifi password is Xk9mP2q"), vec!["Xk9mP2q"]);
        assert_eq!(hits("passwd Xk9mP2q"), vec!["Xk9mP2q"]);
    }

    #[test]
    fn a_decorated_prose_key_masks_the_next_word() {
        assert_eq!(hits("**password**: Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
        assert_eq!(hits("`password` is Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
        assert_eq!(hits("\"password\" is Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
        assert_eq!(hits("'api key': Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
        assert_eq!(hits("__passwd__ Zq7Lm2Xr"), vec!["Zq7Lm2Xr"]);
    }

    #[test]
    fn any_decorated_or_curly_quoted_key_masks_its_value() {
        // security-review B r4: Markdown, backtick and curly-quote marks around a key.
        for text in [
            "`token`: Zq7Lm2Xr",
            "`secret`: Zq7Lm2Xr",
            "`API_KEY`: Zq7Lm2Xr",
            "`OPENAI_API_KEY`: Zq7Lm2Xr",
            "**api_key**: Zq7Lm2Xr",
            "**client_secret**: Zq7Lm2Xr",
            "*Token*: Zq7Lm2Xr",
            "**Token**: Zq7Lm2Xr",
            "**Secret**: Zq7Lm2Xr",
            "**Pass**: Zq7Lm2Xr",
            "**Secret key:** Zq7Lm2Xr",
            "**Private key:** Zq7Lm2Xr",
            "**Access key:** Zq7Lm2Xr",
            "`token` is Zq7Lm2Xr",
            "\"token\" is Zq7Lm2Xr",
            "\u{201c}password\u{201d} is Zq7Lm2Xr",
            "\u{2018}password\u{2019} is Zq7Lm2Xr",
            "\u{201c}password\u{201d}: Zq7Lm2Xr",
            "{\u{201c}password\u{201d}: \u{201c}Zq7Lm2Xr\u{201d}}",
            "my \u{201c}password\u{201d} is Zq7Lm2Xr",
            "\u{201c}token\u{201d}: Zq7Lm2Xr",
            "\u{201c}api key\u{201d} is Zq7Lm2Xr",
            "\u{ab}password\u{bb} is Zq7Lm2Xr",
        ] {
            let found = hits(text);
            assert!(
                found.iter().any(|hit| hit.contains("Zq7Lm2Xr")),
                "{text} leaked: {found:?}"
            );
        }
        // Still clear: a decorated key with no value, and plain prose.
        assert!(hits("the `token` field").is_empty());
        assert!(hits("a \u{201c}secret\u{201d} recipe").is_empty());
    }

    #[test]
    fn a_value_ending_in_marks_is_masked_whole() {
        // K15 seal r1: the marks trimmed to read a value are part of the secret.
        assert_eq!(hits("password is Zq7*****"), vec!["Zq7*****"]);
        assert_eq!(hits("password is Zq7Lm2X*"), vec!["Zq7Lm2X*"]);
        assert_eq!(hits("my password is hunter2}}}"), vec!["hunter2}}}"]);
    }

    #[test]
    fn any_named_key_in_marks_masks_the_value_after_is() {
        // K15 seal r1: underscore marks, camelCase and env-style names.
        for text in [
            "__token__ is Zq7Lm2Xr",
            "_secret_ was Zq7Lm2Xr",
            "__api_key__ is Zq7Lm2Xr",
            "`clientSecret` is Zq7Lm2Xr",
            "\u{201c}accessToken\u{201d} is Zq7Lm2Xr",
            "`authToken` was Zq7Lm2Xr",
            "\u{201c}private_key\u{201d} is Zq7Lm2Xr",
            "`privateKey` is Zq7Lm2Xr",
            "`OPENAI_API_KEY` is Zq7Lm2Xr",
            "the `GITHUB_TOKEN` is Zq7Lm2Xr",
        ] {
            let found = hits(text);
            assert!(
                found.iter().any(|hit| hit.contains("Zq7Lm2Xr")),
                "{text} leaked: {found:?}"
            );
        }
        assert!(hits("the `status` is Zq7Lm2Xr").is_empty());
    }

    #[test]
    fn a_prose_key_followed_by_a_stopword_masks_nothing() {
        assert!(hits("the password manager").is_empty());
        assert!(hits("reset the password for Camille").is_empty());
        assert!(hits("the api key field").is_empty());
        assert!(hits("pwd").is_empty());
        // A dash flag is a secret only in a MySQL or user command.
        assert!(hits("ssh -pTr0ubCliP42 host").is_empty());
    }

    #[test]
    fn a_phrase_scan_reads_each_cue_a_bounded_span() {
        // Cues glued in one long word, and cues one after another, stay linear.
        for text in [
            format!("pin is {}", "a-pin-".repeat(50_000)),
            "pin ".repeat(75_000),
            format!("password for {}", "the ".repeat(75_000)),
            "mot de passe du ".repeat(20_000),
            "mdp est Tr0ub4dor ".repeat(20_000),
            "**password** is Tr0ub4dor ".repeat(20_000),
            "password is set to Tr0ub4dor ".repeat(20_000),
            "-password-".repeat(50_000),
            "__mot-de-passe__ du ".repeat(20_000),
            "`pwd` is the same as ".repeat(20_000),
        ] {
            let start = std::time::Instant::now();
            let _ = hits(&text);
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
        }
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = SecretRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::Secret]);
        assert_eq!(recognizer.name(), "secrets");
    }
}
