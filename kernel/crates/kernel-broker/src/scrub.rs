//! Exact-value redaction of the secrets this process *knows*.
//!
//! The heuristic layers in [`crate::text`] are shape-based: they recognise
//! credential *names* and vendor prefixes, but a value with no name in front
//! of it (a sentence, a tool argument, an encoded copy) is invisible to
//! them. security-review round 5 showed that shape-driven patching is open-ended
//! (H-04), so this module adds a precise first layer instead: every secret
//! Auxesis itself resolves — provider keys (`AUX_KEY_*` from `.env` or the
//! process environment), the API bearer token, and any key the engine loads
//! at runtime — is registered here, and every scrub surface replaces those
//! exact values (and their common transforms) by substring before the
//! heuristic layers run.
//!
//! Guarantees:
//!
//! - **Exact.** Only registered values and their derived encodings match;
//!   the layer is off (zero cost) when the registry is empty.
//! - **Minimum length 8.** A shorter value would make false positives likely
//!   for a substring search, so it is left to the heuristic layers.
//! - **Linear.** One Aho-Corasick automaton over all needles, plus a second
//!   scan over a whitespace/zero-width-condensed copy of the text (so a
//!   value split across lines or stuffed with invisible characters still
//!   matches); both scans and the range merge are linear in the text.
//! - **Never logged, never formatted.** [`KnownSecret`] has a custom `Debug`
//!   impl that prints `<redacted>` and zeroes its buffer on drop; nothing in
//!   this module ever writes a value into a log line or an error message.
//! - **Withheld from streaming output.** [`streaming_hold_bytes`] returns the
//!   fixed trailing window a streaming writer must hold back so a value (or
//!   a heuristic match in progress) cannot leave half-formed; the writer then
//!   emits a prefix of the *whole-buffer* scrub, which never splits a match.
//!
//! The heuristic layers stay as the fallback for secrets this process has
//! never seen; their documented residuals are unchanged.
//!
//! # Scrubber limits (frozen after round 10)
//!
//! The exact-value layer covers a registered value's **raw form plus a closed
//! composition closure of encodings to depth 2**: base64 (standard and
//! URL-safe, padded and unpadded), base32, hex (contiguous, `: - space`
//! separated, `\x`/`0x`), percent-encoding (full, minimal, all-byte), JSON
//! `\u` escapes, HTML entities and NFKC forms, composed in every pair
//! (base64-of-hex, hex-of-base64, percent-of-base64, …). Every registered
//! value's raw form is always a needle; a value longer than
//! [`MAX_KNOWN_SECRET_LEN`] is refused, and a value whose closure exceeds its
//! byte budget — always the case from 410 value bytes, where the `0x`-of-hex
//! composition passes the needle cap — is flagged [`registry_oversized`], so
//! live streams fail closed (whole-message placeholder) instead of silently
//! missing a spelling; registration logs one warning with the source label
//! from 400 bytes up (never the value).
//!
//! No finite closure can be complete: an attacker who can inject instructions
//! can always ask the model for an encoding outside it (ROT13, reversed,
//! letter-spaced, translated, a one-time pad). The **real defences** are that
//! secrets are never placed in model context, untrusted content is tainted,
//! egress is approval-gated, and tool outputs are redacted per turn. This
//! scrubber is defence in depth and is **frozen after this round**: no
//! further spelling families without an explicit owner request.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use aho_corasick::AhoCorasick;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use unicode_normalization::char::{canonical_combining_class, compose, decompose_compatible};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::text::{MASK, PAIR_SKIP_LIMIT, QUOTED_SCAN_LIMIT};

/// Values shorter than this are never registered: a substring search on a
/// short value would redact ordinary text. The heuristic layers still cover
/// short credentials in a recognisable shape.
pub const MIN_KNOWN_SECRET_LEN: usize = 8;

/// Longest registered value. Keys are far shorter; a file that claims
/// otherwise is not a credential and would only make the automaton huge.
pub const MAX_KNOWN_SECRET_LEN: usize = 4096;

/// Upper bound on registered values, so a hostile `.env` cannot turn every
/// later scrub into a multi-thousand-pattern search. When full, the oldest
/// *unpinned* registration is evicted (a rotated key must still be picked
/// up). Values pinned by live streams are never evicted (R7-1/R8).
pub const MAX_KNOWN_SECRETS: usize = 128;

/// Hard ceiling for the pinned case: a registry may grow past
/// [`MAX_KNOWN_SECRETS`] while every value is pinned by a live stream, but
/// never past this. At the ceiling, a new value is refused and the registry
/// reports [`registry_saturated`], so live streams fail closed with a
/// visible placeholder instead of leaking unscrubbed text (R8).
pub const MAX_KNOWN_SECRETS_HARD: usize = MAX_KNOWN_SECRETS * 2;

/// File under the Auxesis home holding headless `AUX_KEY_*` values.
const ENV_FILE: &str = ".env";

/// A value longer than [`MAX_KNOWN_SECRET_LEN`] cannot be registered; the
/// refusal is logged once so an operator sees that a key is not covered
/// rather than assuming it is (R10).
static LONG_REFUSAL_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// File under the Auxesis home holding the API bearer token.
const API_TOKEN_FILE: &str = "api.token";

/// One registered secret value: never printed, zeroed on drop.
///
/// The canonical value lives here wrapped in [`Zeroizing`]; the derived
/// match needles inside the automaton are a copy by construction (the
/// matcher must compare bytes) and live for the process lifetime by design.
struct KnownSecret {
    value: Zeroizing<String>,
    /// Registration sequence (R8 pin table): a value is pinned by a live
    /// stream when its sequence is below the stream's pin cutoff.
    seq: u64,
    /// This value's needle variants, computed once at registration. The
    /// registry union is rebuilt on every mutation; recomputing every value's
    /// variants each time made a cap-sized fill quadratic.
    variants: BTreeSet<String>,
    /// The variant closure exceeded its byte budget, so not every spelling of
    /// this value is covered: live streams fail closed (mask the whole
    /// message) while it is registered.
    oversized: bool,
}

impl KnownSecret {
    fn new(value: &str, seq: u64) -> Self {
        let (variants, oversized) = secret_variants(value);
        Self {
            variants,
            oversized,
            value: Zeroizing::new(value.to_string()),
            seq,
        }
    }

    fn value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for KnownSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KnownSecret(<redacted>)")
    }
}

/// The process-wide registry; empty means the layer is off.
#[derive(Default)]
struct Registry {
    values: Vec<KnownSecret>,
    needles: BTreeSet<String>,
    matcher: Option<AhoCorasick>,
    /// Set when values changed since the automaton was built and the registry
    /// is too large to rebuild inline; the next scrub rebuilds once, so a
    /// cap-sized fill batches instead of rebuilding per registration. Small
    /// registries (the startup keys) rebuild immediately, keeping the first
    /// scrub cheap.
    matcher_dirty: bool,
    max_needle_len: usize,
    /// Bumped on every mutation, so a caller may cache a scrub result and
    /// reuse it only while the registry it was computed against is intact.
    generation: u64,
    /// Next pin epoch handed out by [`pin_known_secrets`].
    next_pin: u64,
    /// Registration sequence the next value receives.
    next_value_seq: u64,
    /// Live pin epochs and the registration-sequence cutoff each pinned: a
    /// value whose `seq` is below a cutoff existed when that pin was taken.
    /// Two `u64`s per live stream, shared here instead of one epoch per
    /// value per stream (R8 P3).
    pins: BTreeMap<u64, u64>,
    /// Maximum cutoff over the live pins (`0` when none): a value is pinned
    /// exactly when `seq < max_pin_cutoff`.
    max_pin_cutoff: u64,
    /// At least one registered value's variant closure exceeded its budget:
    /// live streams fail closed (whole-message placeholder) until it leaves
    /// the registry (R10).
    oversized: bool,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only: no needle ever reaches a formatter.
        f.debug_struct("Registry")
            .field("secrets", &self.values.len())
            .field("needles", &self.needles.len())
            .finish()
    }
}

fn registry() -> &'static RwLock<Registry> {
    static REGISTRY: OnceLock<RwLock<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(Registry::default()))
}

fn read_registry() -> RwLockReadGuard<'static, Registry> {
    // A poisoned lock means a panic elsewhere; the registry itself is still
    // consistent (every mutation happens under the same lock).
    registry().read().unwrap_or_else(|err| err.into_inner())
}

fn write_registry() -> RwLockWriteGuard<'static, Registry> {
    registry().write().unwrap_or_else(|err| err.into_inner())
}

/// Register one known secret value. Returns `true` when it was new.
///
/// Values shorter than [`MIN_KNOWN_SECRET_LEN`], longer than
/// [`MAX_KNOWN_SECRET_LEN`] or blank are refused; at [`MAX_KNOWN_SECRETS`]
/// the least recently registered value is evicted.
pub fn register_known_secret(value: &str) -> bool {
    register_values(std::iter::once(("explicit", value))).0 > 0
}

/// Register every value under one write lock, rebuilding the needle set and
/// the automaton **once** for the whole batch (SB6-08: the startup path used
/// to rebuild both per value, which was quadratic in the key count).
///
/// Returns `(registered, refused)`. A value that is already registered is
/// touched to the back of the eviction order (SB6-07: eviction is LRU, so the
/// key that is still being re-resolved is not the one dropped at the cap).
fn register_values<'a>(values: impl Iterator<Item = (&'a str, &'a str)>) -> (usize, usize) {
    let mut registry = write_registry();
    let mut registered = 0usize;
    let mut refused = 0usize;
    let mut changed = false;
    for (label, value) in values {
        let value = value.trim();
        if value.len() < MIN_KNOWN_SECRET_LEN
            || value.len() > MAX_KNOWN_SECRET_LEN
            || value.bytes().all(|byte| byte.is_ascii_whitespace())
        {
            if value.len() > MAX_KNOWN_SECRET_LEN
                && !LONG_REFUSAL_LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                // Never log the value itself, only the fact of the refusal.
                tracing::warn!(
                    limit = MAX_KNOWN_SECRET_LEN,
                    "a known-secret value is longer than the registration limit and is NOT scrubbed"
                );
            }
            refused += 1;
            continue;
        }
        if let Some(index) = registry
            .values
            .iter()
            .position(|secret| secret.value() == value)
        {
            // Still live: make it the newest entry so a rotated key evicts
            // something that has not been resolved recently.
            if index + 1 != registry.values.len() {
                let secret = registry.values.remove(index);
                registry.values.push(secret);
            }
            continue;
        }
        if registry.values.len() >= MAX_KNOWN_SECRETS {
            // Drop the least recently registered *unpinned* value so a
            // long-running daemon keeps picking up rotated keys at the cap,
            // while a value a live stream still relies on is never silently
            // un-registered (R7-1/R8). If every value is pinned the registry
            // grows up to the hard ceiling; at the ceiling a new value is
            // refused and streams fail closed (R8).
            let cutoff = registry.max_pin_cutoff;
            match registry
                .values
                .iter()
                .position(|secret| secret.seq >= cutoff)
            {
                Some(index) => {
                    registry.values.remove(index);
                }
                None if registry.values.len() >= MAX_KNOWN_SECRETS_HARD => {
                    refused += 1;
                    tracing::warn!(
                        "known-secret registry at its hard ceiling with every value pinned; refusing a new value (streams fail closed)"
                    );
                    continue;
                }
                None => {
                    tracing::debug!(
                        "known-secret registry past its cap with every value pinned by a live stream"
                    );
                }
            }
        }
        if value.len() >= LARGE_VALUE_WARN_BYTES {
            // Never the value itself: only the source label and its size. At
            // this length a composed spelling passes the needle cap, so the
            // value is flagged `registry_oversized` and every live stream
            // fails closed while it is registered (GLM-P3).
            tracing::warn!(
                source = label,
                bytes = value.len(),
                "a known-secret value is at least 400 bytes: its closure exceeds the per-value spelling cap, so live streams fail closed while it is registered"
            );
        }
        let seq = registry.next_value_seq;
        registry.next_value_seq = registry.next_value_seq.wrapping_add(1);
        registry.values.push(KnownSecret::new(value, seq));
        registered += 1;
        changed = true;
    }
    if changed {
        if registry.values.len() <= SMALL_REGISTRY_REBUILD {
            rebuild_registry(&mut registry);
        } else {
            registry.generation = registry.generation.wrapping_add(1);
            registry.matcher_dirty = true;
        }
    }
    (registered, refused)
}

/// Rebuild the needle set and automaton from the current values, and bump
/// the generation so cached scrub results are not reused. Each value's
/// variants are cached, so a cap-sized fill does not recompute every value's
/// spellings on every registration.
fn rebuild_registry(registry: &mut Registry) {
    registry.needles = registry
        .values
        .iter()
        .flat_map(|secret| secret.variants.iter().cloned())
        .collect();
    registry.max_needle_len = registry.needles.iter().map(String::len).max().unwrap_or(0);
    registry.matcher = build_matcher(&registry.needles);
    registry.oversized = registry.values.iter().any(|secret| secret.oversized);
    registry.matcher_dirty = false;
    registry.generation = registry.generation.wrapping_add(1);
}

/// Rebuild the automaton if registrations were batched.
fn ensure_matcher(registry: &mut Registry) {
    if registry.matcher_dirty {
        rebuild_registry(registry);
    }
}

/// Registries at or below this size rebuild their automaton on every change
/// (startup keys, a handful of values); larger ones batch and rebuild on the
/// next scrub, so a cap-sized fill is linear instead of quadratic.
const SMALL_REGISTRY_REBUILD: usize = 8;

/// Pin every currently registered value for the lifetime of a live delta
/// stream (R7-1).
///
/// While pinned, a value is never evicted by the LRU cap, so a mid-turn key
/// re-resolution, a sibling stream's registrations, or a rotation storm
/// cannot silently un-register a secret a live stream still relies on.
/// Returns the epoch to hand back to [`unpin_known_secrets`].
pub fn pin_known_secrets() -> u64 {
    let mut registry = write_registry();
    let epoch = registry.next_pin;
    registry.next_pin = registry.next_pin.wrapping_add(1);
    let cutoff = registry.next_value_seq;
    registry.pins.insert(epoch, cutoff);
    registry.max_pin_cutoff = registry.max_pin_cutoff.max(cutoff);
    epoch
}

/// Release a pin taken by [`pin_known_secrets`] and trim the registry back
/// to its cap by evicting the oldest unpinned values. Values registered
/// after the pin were never protected by it and are not touched.
pub fn unpin_known_secrets(epoch: u64) {
    let mut registry = write_registry();
    registry.pins.remove(&epoch);
    registry.max_pin_cutoff = registry.pins.values().copied().max().unwrap_or(0);
    let cutoff = registry.max_pin_cutoff;
    let mut trimmed = false;
    while registry.values.len() > MAX_KNOWN_SECRETS {
        match registry
            .values
            .iter()
            .position(|secret| secret.seq >= cutoff)
        {
            Some(index) => {
                registry.values.remove(index);
                trimmed = true;
            }
            None => break,
        }
    }
    if trimmed {
        if registry.values.len() <= SMALL_REGISTRY_REBUILD {
            rebuild_registry(&mut registry);
        } else {
            registry.generation = registry.generation.wrapping_add(1);
            registry.matcher_dirty = true;
        }
    }
}

/// True when the registry is at its hard ceiling with every value pinned by
/// a live stream: a new value cannot be registered without evicting a
/// pinned one, so a live delta stream must fail closed (emit a visible
/// placeholder) rather than publish unscrubbed text (R8).
pub fn registry_saturated() -> bool {
    let registry = read_registry();
    let cutoff = registry.max_pin_cutoff;
    registry.values.len() >= MAX_KNOWN_SECRETS_HARD
        && registry.values.iter().all(|secret| secret.seq < cutoff)
}

/// True when a registered value's variant closure exceeded its budget: not
/// every spelling of that value is covered, so a live stream must fail closed
/// (emit a visible placeholder) rather than publish text it cannot prove
/// scrubbed (R10).
pub fn registry_oversized() -> bool {
    read_registry().oversized
}

/// True for the environment and `.env` names whose value is a secret this
/// process resolves: provider keys, the Telegram bot token, one mailbox
/// password per account (`AUX_MAIL_<ID>`; mail hosts and ports live in
/// `mail.toml`, never in `.env`) and an extension's OAuth token bundle
/// (`EXT_<NAME>__OAUTH_TOKENS`).
fn is_known_secret_name(name: &str) -> bool {
    name.starts_with("AUX_KEY_")
        || name == "AUX_TELEGRAM_BOT_TOKEN"
        || name.starts_with("AUX_MAIL_")
        || name.ends_with("__OAUTH_TOKENS")
}

/// Collect one named secret, and for an OAuth bundle the access and refresh
/// tokens it holds: a provider error echoes a token on its own, not the whole
/// JSON line, so the leaves are registered as secrets of their own.
fn push_known_secret(values: &mut Vec<(String, Zeroizing<String>)>, name: &str, value: String) {
    if name.ends_with("__OAUTH_TOKENS") {
        if let Ok(serde_json::Value::Object(fields)) =
            serde_json::from_str::<serde_json::Value>(&value)
        {
            for key in ["access_token", "refresh_token"] {
                if let Some(serde_json::Value::String(token)) = fields.get(key) {
                    values.push((format!("{name}.{key}"), Zeroizing::new(token.clone())));
                }
            }
        }
    }
    values.push((name.to_owned(), Zeroizing::new(value)));
}

/// Register every known secret from `<home>/.env`, the process environment
/// (`AUX_KEY_*`, `AUX_TELEGRAM_BOT_TOKEN`, `AUX_MAIL_*` and
/// `EXT_*__OAUTH_TOKENS`) and `<home>/api.token`. Returns how many values
/// were new.
///
/// Called at daemon start and again whenever a key is re-resolved, so a
/// changed `.env` is picked up without a restart. Never returns or logs a
/// value; SB6-05: the count of values *refused* (too short, too long, blank)
/// is logged at debug so `registered=2` can be reconciled when a third key
/// exists in `.env`.
pub fn register_known_secrets_from_home(home: &Path) -> usize {
    let mut values: Vec<(String, Zeroizing<String>)> = Vec::new();
    for (name, value) in std::env::vars() {
        if is_known_secret_name(&name) {
            push_known_secret(&mut values, &name, value);
        }
    }
    if let Some(text) = read_small_file(&home.join(ENV_FILE)) {
        for (name, value) in dotenv_known_secret_values(&text) {
            push_known_secret(&mut values, &name, value);
        }
    }
    if let Some(token) = read_small_file(&home.join(API_TOKEN_FILE)) {
        values.push((
            API_TOKEN_FILE.to_string(),
            Zeroizing::new(token.trim().to_string()),
        ));
    }
    let (registered, refused) = register_values(
        values
            .iter()
            .map(|(label, value)| (label.as_str(), value.as_str())),
    );
    if refused > 0 {
        tracing::debug!(
            registered,
            refused,
            "known secrets refused at registration (shorter than 8 bytes, longer than 4096 or blank)"
        );
    }
    registered
}

/// Drop every registered secret (tests, key rotation). The values are zeroed
/// by their `Zeroizing` wrapper before the registry is replaced. The
/// generation is bumped so cached scrub results are not reused, and the pin
/// counter keeps rising so a released epoch can never collide with a new one.
pub fn clear_known_secrets() {
    let mut registry = write_registry();
    let generation = registry.generation.wrapping_add(1);
    let next_pin = registry.next_pin;
    *registry = Registry {
        generation,
        next_pin,
        ..Registry::default()
    };
}

/// Monotonic counter bumped whenever the registry changes. A caller that
/// caches a scrub result can reuse it only while this value is unchanged.
pub fn registry_generation() -> u64 {
    read_registry().generation
}

/// Slack above the longest registered spelling: a value can only be held for
/// its own length, so a larger hold means an open construct.
const STREAM_WINDOW_SLACK: usize = 64;

/// Bytes per value byte of the widest registered spelling: `\xNN`/`0xNN` cost
/// four, `%NN` three, and a separator (or an invisible character the
/// condensed scan drops) may sit between units; six covers every documented
/// family with margin.
const SPELLING_EXPANSION: usize = 6;

/// Lower/upper bounds on [`streaming_hold_bytes`]: never less than a small
/// tail, never more than a few KiB, so streaming latency and memory stay
/// bounded even for a hostile registry.
const MIN_STREAM_WINDOW: usize = 256;
const MAX_STREAM_WINDOW: usize = 4096;

/// How far back a name run is scanned before a separator. Mirrors the
/// tokenizer's bounded scans; a construct cannot start further back than
/// this plus its separator and value windows.
const HEURISTIC_NAME_SCAN: usize = 96;

/// Fixed trailing window (bytes) a streaming writer must withhold from a
/// text buffer before emitting a prefix of it.
///
/// The window is derived from the registry, not from the text: the longest
/// registered value may still be spelled out (hex, `\xNN`, `0xNN`, `%NN`,
/// base64, base32, JSON-escaped, case-folded) with separators or invisible
/// characters between its bytes, and a heuristic construct in progress (a
/// pair's value, a `Bearer` keyword, a quoted or unquoted name) may span the
/// tokenizer's bounded scan windows. Holding back this many trailing bytes
/// means a future chunk cannot complete any of those constructs *before* the
/// hold: the whole-buffer scrub of the next state still starts with the same
/// bytes, so a streaming emitter can release the prefix and later match the
/// whole-buffer result exactly.
///
/// The result is clamped to [`MIN_STREAM_WINDOW`]..=[`MAX_STREAM_WINDOW`];
/// a registered value longer than the cap is outside the streaming window
/// contract, but the whole-buffer pass (and therefore the final output) is
/// unaffected.
pub fn streaming_hold_bytes() -> usize {
    let registry = read_registry();
    let longest = registry
        .values
        .iter()
        .map(|secret| secret.value().len())
        .max()
        .unwrap_or(0);
    // An in-progress heuristic construct spans the pair-skip window, a quoted
    // value's scan window and the name before its separator.
    let heuristic = PAIR_SKIP_LIMIT + QUOTED_SCAN_LIMIT + HEURISTIC_NAME_SCAN;
    let expanded = longest
        .saturating_mul(SPELLING_EXPANSION)
        .max(heuristic)
        .saturating_add(STREAM_WINDOW_SLACK);
    expanded.clamp(MIN_STREAM_WINDOW, MAX_STREAM_WINDOW)
}

/// How many times the streaming cut moves back before giving up for this
/// call; the next call happens after more text arrives.
const MAX_STREAM_BACKOFF_ATTEMPTS: usize = 6;

/// Largest raw-prefix length of `raw` a streaming writer may publish now,
/// using the fixed trailing window ([`streaming_hold_bytes`]).
///
/// Contract: the returned prefix
/// * ends on a char boundary and outside a token run,
/// * lies at least one window away from the end of `raw`,
/// * and `crate::text::redact_secrets(&raw[..cut])` is a byte-prefix of the
///   whole-buffer scrub of `raw`.
///
/// A writer that emits `redact_secrets(&raw[..cut])` now and later emits the
/// remainder of `redact_secrets(raw)` therefore streams byte-identical text
/// to the whole-buffer scrub: no mask ever straddles a frame boundary and
/// the final flush equals `redact_secrets(whole)`. Returns `0` while nothing
/// is stable (the window covers the buffer, or a construct cannot be
/// resolved yet).
pub fn stream_prefix_cut(raw: &str) -> usize {
    if raw.is_empty() {
        return 0;
    }
    let window = streaming_hold_bytes();
    let mut cut = run_start(
        raw,
        floor_char_boundary(raw, raw.len().saturating_sub(window)),
    );
    if cut == 0 {
        return 0;
    }
    let whole = crate::text::redact_secrets(raw);
    let mut attempts = 0usize;
    loop {
        let prefix = crate::text::redact_secrets(&raw[..cut]);
        if whole.starts_with(prefix.as_str()) {
            return cut;
        }
        // A mask straddles the cut: move it back before that region.
        let divergence = common_prefix_len(whole.as_bytes(), prefix.as_bytes());
        let back = prefix.len().saturating_sub(divergence).max(1);
        let next = run_start(raw, floor_char_boundary(raw, cut.saturating_sub(back)));
        attempts += 1;
        if next >= cut || next == 0 || attempts >= MAX_STREAM_BACKOFF_ATTEMPTS {
            return 0;
        }
        cut = next;
    }
}

/// If `cut` splits a run, move it to the run's first byte: a token, a vendor
/// key or a JWT is only recognisable whole (or from its own start), so no
/// frame boundary may fall inside one.
fn run_start(text: &str, cut: usize) -> usize {
    if cut == 0 || cut >= text.len() {
        return cut;
    }
    text[..cut]
        .char_indices()
        .rev()
        .take_while(|(at, _)| cut - *at <= MAX_STREAM_WINDOW)
        .find(|(_, ch)| ch.is_whitespace())
        .map_or(0, |(at, ch)| at + ch.len_utf8())
}

/// Floor `at` onto a UTF-8 char boundary of `text`.
fn floor_char_boundary(text: &str, at: usize) -> usize {
    let bytes = text.as_bytes();
    let mut at = at.min(bytes.len());
    while at > 0 && at < bytes.len() && (bytes[at] & 0xC0) == 0x80 {
        at -= 1;
    }
    at
}

/// Longest common byte prefix of two slices.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .take_while(|(left, right)| left == right)
        .count()
}

/// Replace every known value (or derived encoding) found in `text`.
///
/// Returns `None` when the registry is empty or nothing matched, so callers
/// can keep the original bytes without cloning. Matching is linear: one
/// automaton pass over the raw text and one over a condensed copy that drops
/// whitespace and invisible characters, so values split across lines or
/// stuffed with zero-width characters are still found.
pub fn redact_known_secrets(text: &str) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    {
        let registry = read_registry();
        if !registry.matcher_dirty {
            return redact_with_registry(&registry, text);
        }
    }
    let mut registry = write_registry();
    ensure_matcher(&mut registry);
    redact_with_registry(&registry, text)
}

/// [`redact_known_secrets`] against a registry whose automaton is current.
fn redact_with_registry(registry: &Registry, text: &str) -> Option<String> {
    let matcher = registry.matcher.as_ref()?;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for hit in matcher.find_overlapping_iter(text.as_bytes()) {
        ranges.push((hit.start(), hit.end()));
    }
    // SB6-01: a dump or an escaped copy is still the same secret. Scan the
    // text a second time as hex spellings (contiguous or separated by
    // whitespace/colons, `\xNN`/`%NN` escaped, `xxd`/`od`/`hexdump -C`
    // scaffolding) and match the decoded bytes through the same automaton.
    if text.len() <= u32::MAX as usize && text_may_hold_hex(text.as_bytes()) {
        let limit = registry.max_needle_len.saturating_add(1024).max(4096);
        ranges.extend(hex_spelling_ranges(text.as_bytes(), matcher, limit));
    }
    // The condensed copy catches inserted whitespace/newlines and
    // zero-width/invisible characters between a value's bytes. For plain
    // ASCII without whitespace it would be identical, so skip building it.
    let needs_condense = text.bytes().any(|byte| byte.is_ascii_whitespace()) || !text.is_ascii();
    if needs_condense && text.len() <= u32::MAX as usize {
        let (condensed, starts, ends) = condense(text);
        if condensed.len() >= MIN_KNOWN_SECRET_LEN && condensed != text {
            for hit in matcher.find_overlapping_iter(condensed.as_bytes()) {
                let start = starts[hit.start()] as usize;
                let end = ends[hit.end() - 1] as usize;
                ranges.push((start, end));
            }
        }
    }
    // R8: an NFKC-equivalent spelling (`ofﬁce` with a ligature, fullwidth or
    // superscript compatibility forms, a decomposed combining sequence) is
    // the same value to a human and to any NFKC normaliser. Fold the text
    // with real NFKC and match through the same automaton, mapping every hit
    // back to the original span; hex spellings written in compatibility
    // forms are decoded from the folded copy too.
    if text.len() <= u32::MAX as usize && !text.is_ascii() {
        let (folded, starts, ends) = fold_nfkc(text);
        if folded != text {
            for hit in matcher.find_overlapping_iter(folded.as_bytes()) {
                ranges.push((starts[hit.start()] as usize, ends[hit.end() - 1] as usize));
            }
            if text_may_hold_hex(folded.as_bytes()) {
                let limit = registry.max_needle_len.saturating_add(1024).max(4096);
                for (start, end) in hex_spelling_ranges(folded.as_bytes(), matcher, limit) {
                    ranges.push((starts[start] as usize, ends[end - 1] as usize));
                }
            }
        }
    }
    // R8: JSON/JS `\u` escapes — surrogate pairs included — are the same
    // characters; fold them and match, so a mixed spelling (raw text with
    // one escaped character) is caught too. Separated and hex-dump spellings
    // are handled by the decoded-run scanner.
    if text.len() <= u32::MAX as usize && (text.contains("\\u") || text.contains("\\U")) {
        let (unescaped, starts, ends) = fold_unicode_escapes(text);
        if unescaped != text {
            for hit in matcher.find_overlapping_iter(unescaped.as_bytes()) {
                ranges.push((starts[hit.start()] as usize, ends[hit.end() - 1] as usize));
            }
            if text_may_hold_hex(unescaped.as_bytes()) {
                let limit = registry.max_needle_len.saturating_add(1024).max(4096);
                for (start, end) in hex_spelling_ranges(unescaped.as_bytes(), matcher, limit) {
                    ranges.push((starts[start] as usize, ends[end - 1] as usize));
                }
            }
        }
    }
    // Keep the original scans; add matches from each decoded run.
    let mut offset = 0;
    for part in text.split_inclusive(char::is_whitespace) {
        let run = part.trim_end_matches(char::is_whitespace);
        if run.contains(['\\', '%', '&']) {
            let parse = |source: &str, at: usize| {
                let bytes = source.as_bytes();
                match bytes.get(at + 1) {
                    Some(b'\\') => Some(('\\', at + 2)),
                    Some(b'u' | b'U' | b'x' | b'X') => {
                        let (code, _, end) = hex_unit_at(bytes, at)?;
                        Some((char::from_u32(code)?, end))
                    }
                    _ => None,
                }
            };
            // One escape can only create a new match within a needle's reach.
            let mut scan_start = 0;
            let mut scan = run;
            if run.len() > kernel_privacy::decode::MAX_SECRET_DECODE_WORK / 3
                && (run.is_ascii()
                    || run
                        .chars()
                        .all(|c| !is_scrub_noise(c) && !matches!(c, '⟦' | '⟧')))
            {
                let mut markers = run
                    .match_indices(['\\', '%', '&'])
                    .filter(|(at, _)| kernel_privacy::decode::known_escape_at(run, *at, &parse));
                let first = markers.next();
                if first.is_none() {
                    offset += part.len();
                    continue;
                }
                if let (Some((at, _)), None) = (first, markers.next()) {
                    let margin = registry.max_needle_len.saturating_add(1024);
                    scan_start = floor_char_boundary(run, at.saturating_sub(margin));
                    let end = floor_char_boundary(run, at.saturating_add(margin).min(run.len()));
                    scan = &run[scan_start..end];
                }
            }
            let settled = kernel_privacy::DecodedText::scan_known_secret(
                scan,
                &parse,
                &mut |view, starts, bounds| {
                    for hit in matcher.find_overlapping_iter(view.as_bytes()) {
                        let first = starts.partition_point(|at| *at < hit.start());
                        let after = starts.partition_point(|at| *at < hit.end());
                        if first < after {
                            ranges.push((
                                offset + scan_start + bounds[first].0,
                                offset + scan_start + bounds[after - 1].1,
                            ));
                        }
                    }
                },
            );
            if !settled {
                ranges.push((offset, offset + run.len()));
            }
        }
        offset += part.len();
    }
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut copied = 0usize;
    for (start, end) in merged {
        if start > copied {
            out.push_str(&text[copied..start]);
        }
        out.push_str(MASK);
        copied = end;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

/// Every searchable form of one secret: the value itself, its hex spelling
/// (raw, `\xNN`-escaped, dump-separated — SB6-01), percent-encoded (both hex
/// cases), JSON-escaped, base64 (standard and URL-safe, padded and unpadded),
/// base32 (RFC 4648, padded and unpadded), the whole-value case folds and the
/// whitespace/zero-width-condensed form of each.
/// Every needle spelling of one value, plus whether the closure could not be
/// covered completely (a spelling over [`MAX_VARIANT_LEN`], or a depth-2
/// closure over its byte budget; R10: the caller then marks the value
/// fail-closed).
fn secret_variants(value: &str) -> (BTreeSet<String>, bool) {
    let mut variants = BTreeSet::new();
    // A spelling longer than `MAX_VARIANT_LEN` is a mainstream spelling the
    // registry cannot cover: the value is flagged fail-closed.
    let oversized = std::cell::Cell::new(false);
    let mut push = |variant: String| {
        if variant.len() >= MIN_KNOWN_SECRET_LEN {
            if variant.len() <= MAX_VARIANT_LEN {
                variants.insert(variant);
            } else {
                oversized.set(true);
            }
        }
    };
    // The secret and its whole-value case folds: Aho-Corasick is byte-exact,
    // so a log shipper or DB that lowercases text must not defeat the layer
    // (SB6-03). `to_lowercase`/`to_uppercase` are only added when they differ
    // (a no-op copy would just bloat the automaton).
    let mut bases: Vec<String> = vec![value.to_string()];
    // R8: the value's own NFKC form is a needle too, so a registered value
    // containing a ligature or compatibility character still matches the
    // plain spelling (and vice versa through the folded scan).
    let nfkc: String = value.nfkc().collect();
    if nfkc != value && !bases.contains(&nfkc) {
        bases.push(nfkc);
    }
    for folded in [value.to_lowercase(), value.to_uppercase()] {
        if folded != value && !bases.contains(&folded) {
            bases.push(folded);
        }
    }
    // R9: spellings are a composition closure of the transform set, not a
    // fixed list. The primary base gets depth 2 (every pair of transforms:
    // base64-of-hex, hex-of-base64, percent-of-base64, percent-of-hex, …);
    // case folds keep depth 1, and the whole closure is budgeted per value.
    // Exceeding the budget degrades to depth 1 and flags the value
    // fail-closed.
    for (index, base) in bases.iter().enumerate() {
        push(base.clone());
        let mut depth1: Vec<String> = Vec::new();
        for kind in TRANSFORMS.iter() {
            if let Some(variant) = apply_transform(*kind, base) {
                if variant.len() <= MAX_VARIANT_LEN {
                    depth1.push(variant);
                } else {
                    oversized.set(true);
                }
            }
        }
        for variant in &depth1 {
            push(variant.clone());
        }
        // The escaped/braced spellings stay available at depth 1 for every
        // base (`\U00000043`, `\u{43}`, `\u{0043}`).
        push(unicode_escaped(base, "\\U", false));
        push(unicode_escaped(base, "\\U", true));
        for digits in [2usize, 4, 6] {
            push(braced_unicode_escaped(base, digits, false));
            push(braced_unicode_escaped(base, digits, true));
        }
        if index != 0 {
            continue;
        }
        let mut depth2: Vec<String> = Vec::new();
        for first in &depth1 {
            for kind in TRANSFORMS {
                // HTML/JSON escapes of an already-escaped spelling (24x per
                // value byte) are periodic needles that make the automaton
                // build pathological and are not mainstream spellings; they
                // are only composed onto inputs up to one frame long.
                if first.len() > 256
                    && matches!(
                        kind,
                        Transform::HtmlHex
                            | Transform::HtmlDecimal
                            | Transform::JsonEscapesUpper
                            | Transform::JsonEscapesLower
                    )
                {
                    continue;
                }
                if let Some(second) = apply_transform(kind, first) {
                    if second.len() <= MAX_VARIANT_LEN {
                        depth2.push(second);
                    }
                }
            }
        }
        let bytes = base.len()
            + depth1.iter().map(String::len).sum::<usize>()
            + depth2.iter().map(String::len).sum::<usize>();
        if bytes <= MAX_VARIANT_BYTES_PER_VALUE {
            for variant in depth2 {
                push(variant);
            }
        } else {
            // Fail closed: the raw and depth-1 spellings are registered, but
            // not every composed spelling is, so live streams must mask the
            // whole message while this value is registered.
            oversized.set(true);
            tracing::warn!(
                bytes,
                "known-secret variant closure exceeds its byte budget; streams fail closed"
            );
        }
    }
    if let Ok(quoted) = serde_json::to_string(value) {
        if quoted.len() >= 2 {
            let escaped = &quoted[1..quoted.len() - 1];
            push(escaped.to_string());
            if escaped.contains("\\u") {
                push(uppercase_unicode_escapes(escaped));
            }
        }
    }
    // The condense step drops whitespace and invisibles, so a value whose own
    // text contains them still matches its plain spelling.
    let condensed: Vec<String> = variants
        .iter()
        .map(|variant| variant.chars().filter(|c| !is_scrub_noise(*c)).collect())
        .filter(|condensed: &String| condensed.len() >= MIN_KNOWN_SECRET_LEN)
        .collect();
    for variant in condensed {
        variants.insert(variant);
    }
    (variants, oversized.get())
}

/// Hex pairs joined by `separator` (`73:62:36`), both hex cases.
fn hex_separated(value: &str, separator: &str, upper: bool) -> String {
    let pairs: Vec<String> = value
        .bytes()
        .map(|byte| {
            if upper {
                format!("{byte:02X}")
            } else {
                format!("{byte:02x}")
            }
        })
        .collect();
    pairs.join(separator)
}

/// One transform of the variant composition closure (R9).
#[derive(Clone, Copy)]
enum Transform {
    Base64Std,
    Base64StdNoPad,
    Base64Url,
    Base64UrlNoPad,
    Base32,
    Base32NoPad,
    Base32Lower,
    Base32NoPadLower,
    HexLower,
    HexUpper,
    HexColonLower,
    HexColonUpper,
    HexDashLower,
    HexDashUpper,
    HexSpaceLower,
    HexSpaceUpper,
    HexEscapedLower,
    HexEscapedUpper,
    HexZeroXLower,
    HexZeroXUpper,
    PercentUpper,
    PercentLower,
    PercentMinimalUpper,
    PercentMinimalLower,
    PercentAllUpper,
    JsonEscapesUpper,
    JsonEscapesLower,
    HtmlHex,
    HtmlDecimal,
    Nfkc,
}

/// The transform set the closure composes (order defines the depth-2 order,
/// so the mainstream pairs are generated first).
const TRANSFORMS: [Transform; 30] = [
    Transform::Base64Std,
    Transform::Base64StdNoPad,
    Transform::Base64Url,
    Transform::Base64UrlNoPad,
    Transform::HexLower,
    Transform::HexUpper,
    Transform::HexColonLower,
    Transform::HexColonUpper,
    Transform::HexDashLower,
    Transform::HexDashUpper,
    Transform::HexSpaceLower,
    Transform::HexSpaceUpper,
    Transform::PercentUpper,
    Transform::PercentLower,
    Transform::PercentMinimalUpper,
    Transform::PercentMinimalLower,
    Transform::PercentAllUpper,
    Transform::Base32,
    Transform::Base32NoPad,
    Transform::Base32Lower,
    Transform::Base32NoPadLower,
    Transform::HexEscapedLower,
    Transform::HexEscapedUpper,
    Transform::HexZeroXLower,
    Transform::HexZeroXUpper,
    Transform::JsonEscapesUpper,
    Transform::JsonEscapesLower,
    Transform::HtmlHex,
    Transform::HtmlDecimal,
    Transform::Nfkc,
];

/// Budget for one value's depth-2 closure, counted in **bytes** so a 256-byte
/// secret's full closure fits. A closure over budget is dropped whole (depth 1
/// remains) and the value is flagged [`registry_oversized`], which makes live
/// streams fail closed rather than silently miss spellings (R10).
const MAX_VARIANT_BYTES_PER_VALUE: usize = 2 * 1024 * 1024;
/// Longest needle registered: every registered value's raw form must be a
/// needle, so this matches the registration cap. Longer composed spellings
/// are left to the decoded scan.
const MAX_VARIANT_LEN: usize = MAX_KNOWN_SECRET_LEN;
/// Registration warning threshold: a value of 410 bytes or more cannot have
/// every spelling covered (the `0x`-of-hex composition passes the 4096-byte
/// needle cap at 410 value bytes), so it is flagged [`registry_oversized`]
/// and every live stream fails closed while it is registered. The warning
/// names the source label, never the value (GLM-P3); 400 leaves margin.
const LARGE_VALUE_WARN_BYTES: usize = 400;

/// Apply one transform; `None` when it is the identity (or too short to be a
/// useful needle).
fn apply_transform(kind: Transform, value: &str) -> Option<String> {
    let transformed = match kind {
        Transform::Base64Std => STANDARD.encode(value),
        Transform::Base64StdNoPad => STANDARD_NO_PAD.encode(value),
        Transform::Base64Url => URL_SAFE.encode(value),
        Transform::Base64UrlNoPad => URL_SAFE_NO_PAD.encode(value),
        Transform::Base32 => base32_encode(value.as_bytes(), true, false),
        Transform::Base32NoPad => base32_encode(value.as_bytes(), false, false),
        Transform::Base32Lower => base32_encode(value.as_bytes(), true, true),
        Transform::Base32NoPadLower => base32_encode(value.as_bytes(), false, true),
        Transform::HexLower => hex_encode(value, false),
        Transform::HexUpper => hex_encode(value, true),
        Transform::HexColonLower => hex_separated(value, ":", false),
        Transform::HexColonUpper => hex_separated(value, ":", true),
        Transform::HexDashLower => hex_separated(value, "-", false),
        Transform::HexDashUpper => hex_separated(value, "-", true),
        Transform::HexSpaceLower => hex_separated(value, " ", false),
        Transform::HexSpaceUpper => hex_separated(value, " ", true),
        Transform::HexEscapedLower => escaped_hex(value, "\\x", false),
        Transform::HexEscapedUpper => escaped_hex(value, "\\X", true),
        Transform::HexZeroXLower => hex_zero_x(value, false),
        Transform::HexZeroXUpper => hex_zero_x(value, true),
        Transform::PercentUpper => percent_encode(value, true),
        Transform::PercentLower => percent_encode(value, false),
        Transform::PercentMinimalUpper => percent_encode_minimal(value, true),
        Transform::PercentMinimalLower => percent_encode_minimal(value, false),
        Transform::PercentAllUpper => percent_encode_all(value),
        Transform::JsonEscapesUpper => unicode_escaped(value, "\\u", true),
        Transform::JsonEscapesLower => unicode_escaped(value, "\\u", false),
        Transform::HtmlHex => html_entities(value, true),
        Transform::HtmlDecimal => html_entities(value, false),
        Transform::Nfkc => value.nfkc().collect(),
    };
    if transformed == value || transformed.len() < MIN_KNOWN_SECRET_LEN {
        None
    } else {
        Some(transformed)
    }
}

/// `0x73 0x62 …` (one prefix per byte, space-separated), both hex cases.
fn hex_zero_x(value: &str, upper: bool) -> String {
    let pairs: Vec<String> = value
        .bytes()
        .map(|byte| {
            if upper {
                format!("0x{byte:02X}")
            } else {
                format!("0x{byte:02x}")
            }
        })
        .collect();
    pairs.join(" ")
}

/// `&#x43;&#x4e;…` (hex) or `&#67;&#78;…` (decimal) HTML entities, one per
/// character.
fn html_entities(value: &str, hex: bool) -> String {
    let mut out = String::with_capacity(value.len() * 6);
    for c in value.chars() {
        if hex {
            out.push_str(&format!("&#x{:X};", c as u32));
        } else {
            out.push_str(&format!("&#{};", c as u32));
        }
    }
    out
}

/// `%73%62…`: every byte percent-escaped, uppercase hex (the R6 spelling the
/// decoded scan accepts).
fn percent_encode_all(value: &str) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len() * 3);
    for &byte in value.as_bytes() {
        out.push('%');
        out.push(UPPER[(byte >> 4) as usize] as char);
        out.push(UPPER[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Percent-encode only the characters that break URL/query parsing (`%`,
/// `+`, `&`, `=`, `?`, `#`, `;`, space, quotes, angle brackets, backtick);
/// everything else is left as-is. This is the "minimal" complement of
/// [`percent_encode`], which escapes everything outside RFC 3986 unreserved.
fn percent_encode_minimal(value: &str, upper: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digits = if upper { UPPER } else { LOWER };
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        let must_escape = c.is_ascii()
            && matches!(
                c,
                '%' | '+' | '&' | '=' | '?' | '#' | ';' | ' ' | '"' | '\'' | '<' | '>' | '`'
            );
        if must_escape {
            let byte = c as u8;
            out.push('%');
            out.push(digits[(byte >> 4) as usize] as char);
            out.push(digits[(byte & 0x0F) as usize] as char);
        } else {
            out.push(c);
        }
    }
    out
}

/// Lower- or upper-case hex of `value`.
fn hex_encode(value: &str, upper: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digits = if upper { UPPER } else { LOWER };
    let mut out = String::with_capacity(value.len() * 2);
    for &byte in value.as_bytes() {
        out.push(digits[(byte >> 4) as usize] as char);
        out.push(digits[(byte & 0x0F) as usize] as char);
    }
    out
}

/// `\x73\x62…` (the prefix and the digits each in the requested case).
fn escaped_hex(value: &str, prefix: &str, upper: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digits = if upper { UPPER } else { LOWER };
    let mut out = String::with_capacity(value.len() * (prefix.len() + 2));
    for &byte in value.as_bytes() {
        out.push_str(prefix);
        out.push(digits[(byte >> 4) as usize] as char);
        out.push(digits[(byte & 0x0F) as usize] as char);
    }
    out
}

/// `\u0043\U00000043`-style escapes, one per **character**: `\u` uses four
/// hex digits for the BMP and a surrogate pair (`\uD83D\uDE00`) beyond it,
/// `\U` uses eight hex digits. Both hex cases (R7-4/R8).
fn unicode_escaped(value: &str, prefix: &str, upper: bool) -> String {
    let mut out = String::with_capacity(value.len() * (prefix.len() + 8));
    for c in value.chars() {
        let code = c as u32;
        if prefix == "\\U" {
            push_hex_escape(&mut out, prefix, code, 8, upper);
        } else if code > 0xFFFF {
            let (high, low) = surrogate_pair(code);
            push_hex_escape(&mut out, prefix, high, 4, upper);
            push_hex_escape(&mut out, prefix, low, 4, upper);
        } else {
            push_hex_escape(&mut out, prefix, code, 4, upper);
        }
    }
    out
}

/// `\u{43}` / `\u{0043}` / `\u{1F600}`-style escapes, one per character,
/// zero-padded to at least `digits` hex digits, both hex cases.
fn braced_unicode_escaped(value: &str, digits: usize, upper: bool) -> String {
    let mut out = String::with_capacity(value.len() * (digits + 5));
    for c in value.chars() {
        push_hex_escape(&mut out, "\\u{", c as u32, digits, upper);
        out.push('}');
    }
    out
}

/// Push `prefix` followed by `value` as zero-padded hex (`width` digits).
fn push_hex_escape(out: &mut String, prefix: &str, value: u32, width: usize, upper: bool) {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digits = if upper { UPPER } else { LOWER };
    out.push_str(prefix);
    for position in (0..width).rev() {
        out.push(digits[((value >> (4 * position)) & 0x0F) as usize] as char);
    }
}

/// The UTF-16 surrogate pair of a non-BMP code point.
fn surrogate_pair(code: u32) -> (u32, u32) {
    let offset = code - 0x1_0000;
    (0xD800 + (offset >> 10), 0xDC00 + (offset & 0x3FF))
}

/// RFC 4648 base32; `pad` appends `=` to a multiple of eight symbols.
fn base32_encode(bytes: &[u8], pad: bool, lower: bool) -> String {
    const UPPER: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let alphabet = if lower { LOWER } else { UPPER };
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5) + 6);
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for &byte in bytes {
        acc = ((acc << 8) | u64::from(byte)) & 0xFF_FFFF_FFFF;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alphabet[((acc >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(alphabet[((acc << (5 - bits)) & 0x1F) as usize] as char);
    }
    if pad {
        while !out.len().is_multiple_of(8) {
            out.push('=');
        }
    }
    out
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
fn percent_encode(value: &str, upper: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let hex = if upper { UPPER } else { LOWER };
    let mut out = String::with_capacity(value.len() * 3);
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex[(byte >> 4) as usize] as char);
            out.push(hex[(byte & 0x0F) as usize] as char);
        }
    }
    out
}

/// `\u00ab` → `\u00AB` for a JSON-escaped body (both cases are legal).
fn uppercase_unicode_escapes(escaped: &str) -> String {
    let bytes = escaped.as_bytes();
    let mut out = String::with_capacity(escaped.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 6 <= bytes.len()
            && bytes.get(i + 1) == Some(&b'u')
            && bytes[i + 2..i + 6].iter().all(u8::is_ascii_hexdigit)
        {
            out.push_str(&escaped[i..i + 2]);
            out.push_str(&escaped[i + 2..i + 6].to_ascii_uppercase());
            i += 6;
        } else {
            let ch = escaped[i..].chars().next().unwrap_or('\u{FFFD}');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Whitespace, control and invisible characters that may be inserted between
/// a value's bytes. Mirrors `kernel_core::text::sanitize_text`'s dropped set
/// (private there) plus all whitespace.
fn is_scrub_noise(c: char) -> bool {
    if c.is_whitespace() || c.is_control() {
        return true;
    }
    is_noncharacter(c)
        || matches!(
            c,
            '\u{00A0}'
                | '\u{00AD}'
                | '\u{034F}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{115F}'..='\u{1160}'
                | '\u{1680}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{2000}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{2060}'..='\u{206F}'
                | '\u{2800}'
                | '\u{3000}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF0}'..='\u{FFF8}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

fn is_noncharacter(c: char) -> bool {
    let cp = c as u32;
    matches!(c, '\u{FDD0}'..='\u{FDEF}') || (cp >= 0xFFFE && (cp & 0xFFFE) == 0xFFFE)
}

/// Condense `text` for split-value matching: drop every
/// [`is_scrub_noise`] character, keeping per-condensed-byte maps back to the
/// original byte span of the character.
#[allow(clippy::type_complexity)]
fn condense(text: &str) -> (String, Vec<u32>, Vec<u32>) {
    let mut condensed = String::with_capacity(text.len());
    let mut starts: Vec<u32> = Vec::with_capacity(text.len());
    let mut ends: Vec<u32> = Vec::with_capacity(text.len());
    for (offset, c) in text.char_indices() {
        if is_scrub_noise(c) {
            continue;
        }
        condensed.push(c);
        let start = offset as u32;
        let end = (offset + c.len_utf8()) as u32;
        for _ in 0..c.len_utf8() {
            starts.push(start);
            ends.push(end);
        }
    }
    (condensed, starts, ends)
}

/// Fold `text` to NFKC, keeping per-folded-byte maps back to the original
/// character span (R8/R9): compatibility decomposition per character,
/// canonical ordering of combining marks, then the standard canonical
/// recomposition (Hangul L/V/T included). Ligatures, fullwidth forms,
/// superscripts, decomposed combining sequences in any order and conjoining
/// Hangul Jamo all match the same registered value. A hit in the folded copy
/// masks the whole original span of the character(s) it came from.
#[allow(clippy::type_complexity)]
fn fold_nfkc(text: &str) -> (String, Vec<u32>, Vec<u32>) {
    // 1. Compatibility decomposition per character, with its original span.
    let mut parts: Vec<(char, u32, u32)> = Vec::with_capacity(text.len());
    for (offset, c) in text.char_indices() {
        let start = offset as u32;
        let end = (offset + c.len_utf8()) as u32;
        decompose_compatible(c, |part| parts.push((part, start, end)));
    }
    // 2. Canonical ordering: each run of non-starters is stably sorted by
    // canonical combining class (the same rule the `Decompositions` iterator
    // applies).
    canonical_order(&mut parts);
    // 3. Canonical recomposition (the standard last-starter algorithm, which
    // `compose` extends with Hangul L+V+T).
    let mut out: Vec<(char, u32, u32)> = Vec::with_capacity(parts.len());
    let mut composee: Option<(char, u32, u32)> = None;
    let mut last_ccc: Option<u8> = None;
    let mut buffer: Vec<(char, u32, u32)> = Vec::new();
    for (ch, start, end) in parts {
        let ch_class = canonical_combining_class(ch);
        let (k, k_start, k_end) = match composee {
            None => {
                if ch_class != 0 {
                    out.push((ch, start, end));
                    continue;
                }
                composee = Some((ch, start, end));
                continue;
            }
            Some(k) => k,
        };
        match last_ccc {
            None => match compose(k, ch) {
                Some(composed) => composee = Some((composed, k_start, end)),
                None => {
                    if ch_class == 0 {
                        out.push((k, k_start, k_end));
                        composee = Some((ch, start, end));
                    } else {
                        buffer.push((ch, start, end));
                        last_ccc = Some(ch_class);
                    }
                }
            },
            Some(blocked_class) => {
                if blocked_class >= ch_class {
                    if ch_class == 0 {
                        out.push((k, k_start, k_end));
                        out.append(&mut buffer);
                        composee = Some((ch, start, end));
                        last_ccc = None;
                    } else {
                        buffer.push((ch, start, end));
                        last_ccc = Some(ch_class);
                    }
                } else {
                    match compose(k, ch) {
                        Some(composed) => composee = Some((composed, k_start, end)),
                        None => {
                            buffer.push((ch, start, end));
                            last_ccc = Some(ch_class);
                        }
                    }
                }
            }
        }
    }
    if let Some((k, start, end)) = composee {
        out.push((k, start, end));
    }
    out.append(&mut buffer);
    // 4. Build the folded string and the per-byte maps.
    let mut folded = String::with_capacity(text.len());
    let mut starts: Vec<u32> = Vec::with_capacity(text.len());
    let mut ends: Vec<u32> = Vec::with_capacity(text.len());
    for (c, start, end) in out {
        folded.push(c);
        for _ in 0..c.len_utf8() {
            starts.push(start);
            ends.push(end);
        }
    }
    (folded, starts, ends)
}

/// Canonical ordering: stably sort every maximal run of non-starters by
/// canonical combining class. The runs are delimited by starters (ccc 0) and
/// the tail.
fn canonical_order(parts: &mut [(char, u32, u32)]) {
    let mut ready = 0usize;
    for index in 0..parts.len() {
        if canonical_combining_class(parts[index].0) == 0 {
            parts[ready..index].sort_by_key(|(c, _, _)| canonical_combining_class(*c));
            ready = index + 1;
        }
    }
    parts[ready..].sort_by_key(|(c, _, _)| canonical_combining_class(*c));
}

/// Fold `\uXXXX`, `\UXXXXXXXX` and `\u{…}` escapes (surrogate pairs
/// included) to their characters, keeping per-folded-byte maps back to the
/// original escape span (R8). This catches mixed spellings — a raw value
/// with one escaped character — that no contiguous needle covers.
#[allow(clippy::type_complexity)]
fn fold_unicode_escapes(text: &str) -> (String, Vec<u32>, Vec<u32>) {
    let bytes = text.as_bytes();
    let mut folded = String::with_capacity(text.len());
    let mut starts: Vec<u32> = Vec::with_capacity(text.len());
    let mut ends: Vec<u32> = Vec::with_capacity(text.len());
    let mut i = 0usize;
    while i < text.len() {
        if bytes.get(i) == Some(&b'\\') && matches!(bytes.get(i + 1), Some(b'u' | b'U')) {
            if let Some((code, start, next)) = unicode_unit_at(bytes, i) {
                if let Some(c) = char::from_u32(code) {
                    folded.push(c);
                    let start = start as u32;
                    let end = next as u32;
                    for _ in 0..c.len_utf8() {
                        starts.push(start);
                        ends.push(end);
                    }
                    i = next;
                    continue;
                }
            }
        }
        let c = text[i..].chars().next().unwrap_or('\u{FFFD}');
        folded.push(c);
        let start = i as u32;
        let end = (i + c.len_utf8()) as u32;
        for _ in 0..c.len_utf8() {
            starts.push(start);
            ends.push(end);
        }
        i += c.len_utf8();
    }
    (folded, starts, ends)
}

/// Decoded bytes of a hex spelling in progress, with the source span of every
/// byte so a match on the decoded buffer maps back onto the text.
#[derive(Default)]
struct HexDecode {
    bytes: Vec<u8>,
    starts: Vec<u32>,
    ends: Vec<u32>,
}

impl HexDecode {
    fn push(&mut self, byte: u8, start: usize, end: usize) {
        self.bytes.push(byte);
        self.starts.push(start as u32);
        self.ends.push(end as u32);
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Match the decoded bytes through the same automaton and record the
    /// original spans; then start a new run. Flushing at `limit` decoded
    /// bytes can never split a match (a match is shorter than the limit).
    fn flush(&mut self, matcher: &AhoCorasick, ranges: &mut Vec<(usize, usize)>) {
        if self.bytes.len() >= MIN_KNOWN_SECRET_LEN {
            for hit in matcher.find_overlapping_iter(self.bytes.as_slice()) {
                ranges.push((
                    self.starts[hit.start()] as usize,
                    self.ends[hit.end() - 1] as usize,
                ));
            }
        }
        self.bytes.clear();
        self.starts.clear();
        self.ends.clear();
    }
}

/// Cheap pre-check so ordinary text (no two adjacent hex digits) skips the
/// two decode passes entirely.
fn text_may_hold_hex(bytes: &[u8]) -> bool {
    bytes
        .windows(2)
        .any(|pair| hex_digit(pair[0]).is_some() && hex_digit(pair[1]).is_some())
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Every span of `text` that is a hex spelling of a registered needle: the
/// contiguous spelling (SB6-01), pairs separated by arbitrary whitespace or
/// `:`, `\xNN`/`\XNN`/`0xNN`/`%NN` escapes, and `xxd`/`od`/`hexdump -C`
/// output (offset column and ASCII column included). The text is decoded in
/// one pass per shape and the decoded bytes are matched through the same
/// automaton, so the cost stays linear in the text and the needle set is
/// never compiled into a backtracking pattern.
fn hex_spelling_ranges(bytes: &[u8], matcher: &AhoCorasick, limit: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    flex_hex_ranges(bytes, matcher, limit, &mut ranges);
    dump_hex_ranges(bytes, matcher, limit, &mut ranges);
    ranges
}

/// Pairs that are separated rather than contiguous: `73 62:36\n6b`,
/// `73-62-36`, `73.62.36`, `73_62_36`, `\x73\x62`, `%73%62`, `0x73 0x62`.
fn flex_hex_ranges(
    bytes: &[u8],
    matcher: &AhoCorasick,
    limit: usize,
    ranges: &mut Vec<(usize, usize)>,
) {
    let mut run = HexDecode::default();
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some((code, start, next)) = hex_unit_at(bytes, i) {
            // One unit can encode up to four UTF-8 bytes (a surrogate pair or
            // a non-BMP `\U`/`\u{…}` escape); every byte maps back to the
            // unit's span.
            let mut encoded = [0u8; 4];
            if let Some(c) = char::from_u32(code) {
                for &byte in c.encode_utf8(&mut encoded).as_bytes() {
                    run.push(byte, start, next);
                }
            }
            if run.len() >= limit {
                run.flush(matcher, ranges);
            }
            i = next;
            continue;
        }
        if is_hex_separator(bytes[i]) {
            i += 1;
            continue;
        }
        run.flush(matcher, ranges);
        i += 1;
    }
    run.flush(matcher, ranges);
}

/// One encoded unit at `p` decoded to a Unicode code point: `73`, `\x73`,
/// `\X73`, `0x73`, `%73`, or the unicode escapes `\u0073`, `\U00000073`,
/// `\u{73}`, `\u{0073}` — including surrogate pairs (`\uD83D\uDE00`) for
/// non-BMP characters (R7-4/R8).
fn hex_unit_at(bytes: &[u8], p: usize) -> Option<(u32, usize, usize)> {
    if bytes.get(p) == Some(&b'\\') && matches!(bytes.get(p + 1), Some(b'u' | b'U')) {
        return unicode_unit_at(bytes, p);
    }
    let mut q = p;
    match bytes.get(p) {
        Some(b'\\') if matches!(bytes.get(p + 1), Some(b'x' | b'X')) => q = p + 2,
        Some(b'%') => q = p + 1,
        Some(b'0') if matches!(bytes.get(p + 1), Some(b'x' | b'X')) => q = p + 2,
        _ => {}
    }
    let hi = hex_digit(*bytes.get(q)?)?;
    let lo = hex_digit(*bytes.get(q + 1)?)?;
    Some((u32::from((hi << 4) | lo), p, q + 2))
}

/// `\u0073` / `\U00000073` (fixed width) and `\u{73}` / `\u{0073}` (braced),
/// with `\uD83D\uDE00` surrogate pairs composed into one code point (R8).
fn unicode_unit_at(bytes: &[u8], p: usize) -> Option<(u32, usize, usize)> {
    let fixed = bytes.get(p + 1) == Some(&b'U');
    let width = if fixed { 8 } else { 4 };
    let mut q = p + 2;
    let mut braced = false;
    let mut value = 0u32;
    if bytes.get(q) == Some(&b'{') {
        braced = true;
        q += 1;
        let mut digits = 0usize;
        while let Some(digit) = hex_digit(*bytes.get(q)?) {
            value = value.checked_mul(16)?.checked_add(u32::from(digit))?;
            digits += 1;
            q += 1;
            if digits > 6 {
                return None;
            }
        }
        if digits == 0 || bytes.get(q) != Some(&b'}') {
            return None;
        }
        q += 1;
    } else {
        for _ in 0..width {
            let digit = hex_digit(*bytes.get(q)?)?;
            value = value.checked_mul(16)?.checked_add(u32::from(digit))?;
            q += 1;
        }
    }
    // A `\uXXXX` high surrogate must be followed by its `\uXXXX` low
    // surrogate: the pair decodes to one non-BMP code point.
    if !fixed && !braced && (0xD800..=0xDBFF).contains(&value) {
        let mut low_q = q;
        if bytes.get(low_q) == Some(&b'\\') && bytes.get(low_q + 1) == Some(&b'u') {
            low_q += 2;
            let mut low = 0u32;
            for _ in 0..4 {
                let digit = hex_digit(*bytes.get(low_q)?)?;
                low = low.checked_mul(16)?.checked_add(u32::from(digit))?;
                low_q += 1;
            }
            if (0xDC00..=0xDFFF).contains(&low) {
                let code = 0x1_0000 + ((value - 0xD800) << 10) + (low - 0xDC00);
                return Some((code, p, low_q));
            }
        }
        return None;
    }
    if (0xD800..=0xDFFF).contains(&value) {
        return None;
    }
    char::from_u32(value)?;
    Some((value, p, q))
}

/// Separators the hex decoders accept between two encoded bytes: a dump may
/// join its pairs with `:`, `-`, `,`, `.`, `_` or `|`, or with whitespace.
fn is_hex_separator(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b':' | b'-' | b',' | b'.' | b'_' | b'|')
}

/// Line-oriented pass for dump output: `xxd`, `od` and `hexdump -C` print an
/// offset column and (except `od`) an ASCII column between the byte pairs.
/// The offset is dropped and the hex column is decoded up to the ASCII
/// column; anything else on the line ends it.
fn dump_hex_ranges(
    bytes: &[u8],
    matcher: &AhoCorasick,
    limit: usize,
    ranges: &mut Vec<(usize, usize)>,
) {
    let mut run = HexDecode::default();
    let mut start = 0usize;
    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset);
        if !dump_line_into(&mut run, matcher, ranges, limit, bytes, start, end) {
            run.flush(matcher, ranges);
        }
        start = end + 1;
    }
    run.flush(matcher, ranges);
}

/// Decode the hex column of one line. Returns `true` when the line looks like
/// dump output; `false` ends the current run.
fn dump_line_into(
    run: &mut HexDecode,
    matcher: &AhoCorasick,
    ranges: &mut Vec<(usize, usize)>,
    limit: usize,
    bytes: &[u8],
    start: usize,
    end: usize,
) -> bool {
    let mut line_end = end;
    while line_end > start && matches!(bytes[line_end - 1], b' ' | b'\t' | b'\r') {
        line_end -= 1;
    }
    if start >= line_end {
        return false;
    }
    // First token and the start of the second (if any), to recognise the
    // offset column of a tool that always prints one.
    let mut first_end = start;
    while first_end < line_end && !matches!(bytes[first_end], b' ' | b'\t') {
        first_end += 1;
    }
    let mut second_start = first_end;
    while second_start < line_end && matches!(bytes[second_start], b' ' | b'\t') {
        second_start += 1;
    }
    let mut cursor = if hex_digit(bytes[start]).is_some()
        && second_start < line_end
        && is_offset_token(&bytes[start..first_end])
    {
        second_start
    } else {
        start
    };
    let mut any = false;
    while cursor < line_end {
        if matches!(bytes[cursor], b' ' | b'\t') {
            cursor += 1;
            continue;
        }
        let token_start = cursor;
        while cursor < line_end && !matches!(bytes[cursor], b' ' | b'\t') {
            cursor += 1;
        }
        if bytes[token_start] == b'|' {
            // `hexdump -C`'s ASCII column.
            break;
        }
        // Colon-separated pairs inside one token (`73:62:36`).
        let mut seg_start = token_start;
        let mut broken = false;
        loop {
            let seg_end = bytes[seg_start..cursor]
                .iter()
                .position(|byte| *byte == b':')
                .map_or(cursor, |offset| seg_start + offset);
            if seg_end > seg_start {
                let segment = &bytes[seg_start..seg_end];
                if !segment.len().is_multiple_of(2)
                    || !segment.iter().all(|byte| hex_digit(*byte).is_some())
                {
                    broken = true;
                    break;
                }
                let mut k = 0usize;
                while k < segment.len() {
                    let hi = hex_digit(segment[k]).unwrap_or(0);
                    let lo = hex_digit(segment[k + 1]).unwrap_or(0);
                    run.push((hi << 4) | lo, seg_start + k, seg_start + k + 2);
                    any = true;
                    k += 2;
                    if run.len() >= limit {
                        run.flush(matcher, ranges);
                    }
                }
            }
            if seg_end >= cursor {
                break;
            }
            seg_start = seg_end + 1;
            if seg_start >= cursor {
                break;
            }
        }
        if broken {
            // The ASCII column (or an alien token) starts here; the rest of
            // the line belongs to it.
            break;
        }
    }
    any
}

/// An offset column token: all hex digits, optionally closed by `:`, at most
/// 16 digits (a 64-bit offset).
fn is_offset_token(token: &[u8]) -> bool {
    let token = if token.last() == Some(&b':') {
        &token[..token.len() - 1]
    } else {
        token
    };
    !token.is_empty() && token.len() <= 16 && token.iter().all(|byte| hex_digit(*byte).is_some())
}

fn build_matcher(needles: &BTreeSet<String>) -> Option<AhoCorasick> {
    if needles.is_empty() {
        return None;
    }
    AhoCorasick::new(needles.iter()).ok()
}

/// Read a small regular file (never a FIFO/device, never more than 1 MiB).
fn read_small_file(path: &Path) -> Option<String> {
    const MAX_BYTES: u64 = 1024 * 1024;
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Every known-secret value from a dotenv file, quotes stripped like the
/// app's `DotEnvStore` does. The name filter is [`is_known_secret_name`], so
/// a new secret family is read here as soon as it is added there.
fn dotenv_known_secret_values(text: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !is_known_secret_name(name) {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|rest| rest.strip_suffix('\''))
            })
            .unwrap_or(value);
        if !value.is_empty() {
            values.push((name.to_string(), value.to_string()));
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    mod redaction_canaries {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/redaction_canaries.rs"
        ));
    }

    /// The registry is process-wide; tests that mutate it take this lock so
    /// they never race each other (other test modules only read it, and the
    /// values here are unique canaries).
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn shared_secret_redaction_canaries_are_removed_from_registered_values() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        for canary in redaction_canaries::CANARIES {
            register_known_secret(canary.secret);
        }
        redaction_canaries::assert_no_canaries(|text| {
            redact_known_secrets(text).unwrap_or_else(|| text.to_string())
        });
        clear_known_secrets();
    }

    fn unique(tag: &str) -> String {
        // Assembled at runtime; short enough that the secret scanner never
        // sees a vendor-shaped literal.
        format!("CANARY_KS_{tag}_{}", "7f3a9c2e1b5d")
    }

    /// Independent hex encoder (deliberately not `super::hex_encode`, so a
    /// broken fix cannot make the test agree with it).
    fn test_hex(value: &str, upper: bool) -> String {
        let mut out = String::new();
        for byte in value.bytes() {
            out.push_str(&format!("{byte:02x}"));
        }
        if upper {
            out = out.to_ascii_uppercase();
        }
        out
    }

    /// Independent base32 (RFC 4648) encoder for the test's own expectations.
    fn test_base32(value: &str, pad: bool, lower: bool) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        for chunk in value.as_bytes().chunks(5) {
            let mut buffer = [0u8; 5];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let bits = chunk.len() * 8;
            let symbols = bits.div_ceil(5);
            for index in 0..symbols {
                let mut symbol = 0u8;
                for bit in 0..5 {
                    let position = index * 5 + bit;
                    let byte = buffer[position / 8];
                    let value = (byte >> (7 - position % 8)) & 1;
                    symbol = (symbol << 1) | value;
                }
                out.push(ALPHABET[symbol as usize] as char);
            }
        }
        if pad {
            while !out.len().is_multiple_of(8) {
                out.push('=');
            }
        }
        if lower {
            out = out.to_ascii_lowercase();
        }
        out
    }

    /// `xxd`-shaped dump: offset, hex column, ASCII column.
    fn xxd_dump(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = String::new();
        for (line, chunk) in bytes.chunks(16).enumerate() {
            let mut hex = String::new();
            for (index, byte) in chunk.iter().enumerate() {
                if index > 0 && index % 2 == 0 {
                    hex.push(' ');
                }
                hex.push_str(&format!("{byte:02x}"));
            }
            let ascii: String = chunk
                .iter()
                .map(|byte| {
                    if (0x20..0x7F).contains(byte) {
                        *byte as char
                    } else {
                        '.'
                    }
                })
                .collect();
            out.push_str(&format!("{:08x}: {hex:<39} {ascii}\n", line * 16));
        }
        out
    }

    /// `hexdump -C`-shaped dump: offset, spaced bytes, piped ASCII column.
    fn hexdump_dump(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = String::new();
        for (line, chunk) in bytes.chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
            let ascii: String = chunk
                .iter()
                .map(|byte| {
                    if (0x20..0x7F).contains(byte) {
                        *byte as char
                    } else {
                        '.'
                    }
                })
                .collect();
            out.push_str(&format!(
                "{:08x}  {}  |{ascii}|\n",
                line * 16,
                hex.join(" ")
            ));
        }
        out
    }

    /// `od -A n -t x1`-shaped dump: no offset column, spaced bytes.
    fn od_dump(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(16) {
            let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
            out.push_str(&format!(" {}\n", hex.join("  ")));
        }
        out
    }

    #[test]
    fn known_values_are_redacted_without_any_name_in_front() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("PLAIN");
        assert!(register_known_secret(&secret));
        let raw = format!("please use {secret} to sign in");
        let clean = redact_known_secrets(&raw).expect("known value must match");
        assert!(!clean.contains(&secret), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        // The shared entry point runs the layer first, so this is redacted
        // even though no heuristic rule can see a value with no name.
        let shared = crate::text::redact_secrets(&raw);
        assert!(!shared.contains(&secret), "{shared}");
        // Unrelated text stays `None` (the layer allocates nothing).
        assert!(redact_known_secrets("an ordinary sentence").is_none());
        let accented = format!("é{secret}");
        assert!(register_known_secret(&accented));
        assert!(redact_known_secrets("literal \\xE9, \\n, and é in docs").is_none());
        let large = format!("é{}\\n\\xE9", "z".repeat(4 * 1024 * 1024));
        assert!(redact_known_secrets(&large).is_none());
        let invalid = format!("{}\\n\\m", "z".repeat(4 * 1024 * 1024));
        assert!(redact_known_secrets(&invalid).is_none());
        let text = format!("before \\xE9{secret} after");
        assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        clear_known_secrets();
    }

    fn nested_first_byte(secret: &str, layers: usize) -> String {
        let mut head = format!("\\x{:02x}", secret.as_bytes()[0]);
        for _ in 1..layers {
            head = head.replace('\\', "\\u005c");
        }
        format!("{head}{}", &secret[1..])
    }

    #[test]
    fn scrub_u_esc_nested_escape_layers_of_a_known_value_are_masked() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("NESTED");
        assert!(register_known_secret(&secret));
        for layers in [1, 2, 3, 10] {
            let spelling = nested_first_byte(&secret, layers);
            let text = format!("before {spelling} after");
            assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        }
        clear_known_secrets();
    }

    #[test]
    fn scrub_u_esc_mixed_escape_families_decode_together() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("MIXED");
        assert!(register_known_secret(&secret));
        let spelling = format!(
            "\\u{:04x}\\x{:02x}%{:02x}{}",
            secret.as_bytes()[0],
            secret.as_bytes()[1],
            secret.as_bytes()[2],
            &secret[3..]
        );
        let text = format!("before {spelling} after");
        assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        for head in ["%5Cu0043", "\\\\u0043", "\\u005cx43"] {
            let text = format!("before {head}{} after", &secret[1..]);
            assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        }
        let tail = unique("OCTAL");
        assert!(register_known_secret(&format!("Ā{tail}")));
        assert!(redact_known_secrets(&format!("\\400{tail}")).is_none());
        clear_known_secrets();
    }

    macro_rules! escape_regression {
        ($name:ident, $plain:literal, $escaped:literal) => {
            #[test]
            fn $name() {
                let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
                clear_known_secrets();
                let tail = unique("ESC");
                assert!(register_known_secret(&format!("{}{tail}", $plain)));
                let clean = redact_known_secrets(&format!("{}{tail}", $escaped));
                assert_eq!(clean.as_deref(), Some("<redacted>"));
                clear_known_secrets();
            }
        };
    }
    escape_regression!(scrub_u_esc_json_slash, "sensitive/", r"sensitive\/");
    escape_regression!(scrub_u_esc_octal, "sensitive-", r"\163ensitive-");
    escape_regression!(scrub_u_esc_percent_u, "sensitive-", "%u0073ensitive-");
    escape_regression!(scrub_u_esc_octal_max, "ÿ7", r"\3777");
    escape_regression!(scrub_u_esc_percent_u_surrogates, "😀", "%uD83D%uDE00");

    #[test]
    fn scrub_u_esc_escape_run_split_across_stream_chunks_is_withheld() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("STREAM");
        assert!(register_known_secret(&secret));
        let encode = |s: &str| s.bytes().map(|b| format!("\\u{b:04x}")).collect::<String>();
        let spelling = encode(&encode(&encode(&secret)));
        let prefix = "public ".repeat(100);
        let split = spelling.len() / 2 + 1;
        let partial = format!("{prefix}{}", &spelling[..split]);
        let cut = stream_prefix_cut(&partial);
        assert!(cut <= prefix.len(), "a partial escape run was published");
        let whole = format!("{prefix}{spelling} end");
        assert!(crate::text::redact_secrets(&whole)
            .starts_with(&crate::text::redact_secrets(&partial[..cut])));
        clear_known_secrets();
    }

    #[test]
    fn scrub_u_esc_unresolved_escape_run_fails_closed_at_the_pass_cap() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("CAP");
        assert!(register_known_secret(&secret));
        let spelling = nested_first_byte(&secret, 20);
        let text = format!("before {spelling} after");
        assert!(redact_known_secrets(&text).as_deref() == Some("before <redacted> after"));
        let oversized = format!("before {}{spelling} after", "z".repeat(4 * 1024 * 1024));
        assert!(redact_known_secrets(&oversized).as_deref() == Some("before <redacted> after"));
        let settled = format!(
            "{}{}",
            "\\u007a".repeat(100),
            nested_first_byte("unrelated", 16)
        );
        assert!(redact_known_secrets(&settled).is_none());
        clear_known_secrets();
    }

    #[test]
    fn scrub_u_esc_large_input_with_escaped_known_value_finishes_and_masks() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("LARGE");
        assert!(register_known_secret(&secret));
        let spelling = nested_first_byte(&secret, 3);
        let text = format!("{}{spelling} end", "z".repeat(200_000));
        let start = std::time::Instant::now();
        let clean = redact_known_secrets(&text).expect("escaped value must be masked");
        assert!(start.elapsed() < std::time::Duration::from_secs(30));
        assert!(clean.ends_with("<redacted> end"));
        clear_known_secrets();
    }

    #[test]
    fn transformed_copies_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("TRANSFORM");
        assert!(register_known_secret(&secret));

        let base64 = STANDARD.encode(secret.as_bytes());
        let encoded = percent_encode(&secret, true);
        let json = serde_json::to_string(&secret).unwrap();
        let split = format!(
            "{}\n  {}",
            &secret[..secret.len() / 2],
            &secret[secret.len() / 2..]
        );
        let zero_width = format!("{}\u{200b}{}", &secret[..4], &secret[4..]);
        let cases = [secret.clone(), base64, encoded, json, split, zero_width];
        for case in cases {
            let raw = format!("value {case} end");
            let clean = redact_known_secrets(&raw)
                .unwrap_or_else(|| panic!("no match for transformed case {case:?}"));
            assert!(!clean.contains(&secret), "leaked via {case:?}: {clean}");
        }
        clear_known_secrets();
    }

    #[test]
    fn hex_encoded_known_values_are_redacted_in_every_dump_spelling() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("HEX");
        assert!(register_known_secret(&secret));

        let lower = test_hex(&secret, false);
        let upper = test_hex(&secret, true);
        let escaped: String = secret
            .bytes()
            .map(|byte| format!("\\x{byte:02x}"))
            .collect();
        let escaped_spaced: String = secret
            .bytes()
            .map(|byte| format!("\\x{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let zero_x_spaced: String = secret
            .bytes()
            .map(|byte| format!("0x{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let pairs: Vec<String> = secret.bytes().map(|byte| format!("{byte:02x}")).collect();
        let spaced = pairs.join(" ");
        let colon = pairs.join(":");
        let newline = pairs.join("\n");
        let xxd = xxd_dump(&secret);
        let hexdump = hexdump_dump(&secret);
        let od = od_dump(&secret);
        // SB6-01: the exact-value layer must see every one of these as the
        // same secret, with or without a credential name in front of it.
        let cases: Vec<(&str, String)> = vec![
            ("hex-lower", lower.clone()),
            ("hex-upper", upper.clone()),
            ("escaped", escaped.clone()),
            ("escaped-spaced", escaped_spaced.clone()),
            ("spaced", spaced.clone()),
            ("zero-x-spaced", zero_x_spaced.clone()),
            ("colon", colon.clone()),
            ("newline", newline.clone()),
            ("xxd", xxd.clone()),
            ("hexdump", hexdump.clone()),
            ("od", od.clone()),
        ];
        for (label, spelling) in cases {
            let text = format!("free text\n{spelling}\ninside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for {label} spelling"));
            assert!(clean.contains(MASK), "{label}: no marker in {clean:?}");
            assert!(
                !clean.contains(&spelling),
                "{label}: spelling survived as {clean:?}"
            );
        }
        // The dumps are line-shaped: the whole hex/ASCII block must be gone,
        // not just a single line of it.
        for (label, dump, first_pairs) in [
            ("xxd", &xxd, "7362 366b 3758 7132"),
            ("hexdump", &hexdump, "73 62 36 6b"),
            ("od", &od, "73  62  36  6b"),
        ] {
            let clean = redact_known_secrets(dump).unwrap_or_else(|| panic!("no {label} match"));
            assert!(
                !clean.contains(first_pairs),
                "{label}: first pairs survived: {clean:?}"
            );
        }
        // The plain spellings that happen to be hex are untouched when no
        // secret is registered.
        clear_known_secrets();
        assert!(redact_known_secrets(&format!("free text {spaced} inside")).is_none());
    }

    #[test]
    fn case_folded_copies_of_a_known_value_are_redacted() {
        // SB6-03: Aho-Corasick is byte-exact, so a log shipper or DB that
        // lower/upper-cases text must not defeat the exact layer. The canary
        // is mixed-case on purpose.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("CaseFold");
        assert!(register_known_secret(&secret));
        assert_ne!(secret.to_lowercase(), secret);
        assert_ne!(secret.to_uppercase(), secret);
        for (label, folded) in [
            ("lower", secret.to_lowercase()),
            ("upper", secret.to_uppercase()),
        ] {
            let text = format!("free text {folded} inside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for case-folded {label}"));
            assert!(clean.contains(MASK), "case-folded {label}: {clean:?}");
        }
        clear_known_secrets();
    }

    #[test]
    fn base32_and_base64url_copies_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("BASEFOLD");
        assert!(register_known_secret(&secret));
        let base32_pad = test_base32(&secret, true, false);
        let base32_plain = test_base32(&secret, false, false);
        let base32_lower = test_base32(&secret, true, true);
        let b64url = URL_SAFE_NO_PAD.encode(secret.as_bytes());
        for (label, case) in [
            ("base32-pad", base32_pad),
            ("base32-nopad", base32_plain),
            ("base32-lower", base32_lower),
            ("base64url-nopad", b64url),
        ] {
            let text = format!("free text {case} inside");
            let clean =
                redact_known_secrets(&text).unwrap_or_else(|| panic!("no match for {label}"));
            assert!(clean.contains(MASK), "{label}: {clean:?}");
            assert!(!clean.contains(&case), "{label}: {clean:?}");
        }
        clear_known_secrets();
    }

    #[test]
    fn percent_encoded_known_value_without_a_name_is_redacted() {
        // M12 pin: the percent-encoded needle is load-bearing. The heuristic
        // layers do not see this string as a credential (there is no name in
        // front of it and no `%3A%2F%2F` DSN shape), so dropping the
        // `percent_encode` needles from `secret_variants` makes this test
        // fail.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = format!("{}{}", "CANARY_KS_PCT_", "7f3a9c+2e/1b5d!");
        assert!(register_known_secret(&secret));
        let upper = percent_encode(&secret, true);
        let lower = percent_encode(&secret, false);
        assert_ne!(upper, secret, "the canary must actually percent-encode");
        for (label, spelling) in [("upper", &upper), ("lower", &lower)] {
            let text = format!("free text {spelling} inside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for percent-{label}"));
            assert!(clean.contains(MASK), "percent-{label}: {clean:?}");
        }
        clear_known_secrets();
    }

    #[test]
    fn streaming_hold_window_stays_within_its_bounds() {
        // The window is always in [MIN, MAX], whatever the registry holds,
        // and a registered value widens the spelling budget. (Values longer
        // than the cap are outside the streaming window contract; the whole
        // buffer pass still covers them.)
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let window = streaming_hold_bytes();
        assert!(
            (MIN_STREAM_WINDOW..=MAX_STREAM_WINDOW).contains(&window),
            "window out of bounds: {window}"
        );
        let secret = format!("{}{}", "WINDOW", "W".repeat(64));
        assert!(register_known_secret(&secret));
        let window = streaming_hold_bytes();
        assert!(
            (MIN_STREAM_WINDOW..=MAX_STREAM_WINDOW).contains(&window),
            "window out of bounds after registration: {window}"
        );
        let expanded =
            (secret.len() * SPELLING_EXPANSION + STREAM_WINDOW_SLACK).min(MAX_STREAM_WINDOW);
        assert!(
            window >= expanded,
            "the registered value must widen the window: {window} < {expanded}"
        );
        clear_known_secrets();
    }

    #[test]
    fn secrets_in_json_keys_are_redacted_by_the_tree_walker() {
        // E6-02: `scrub_json_value` only walked values, so a secret used as a
        // JSON *key* survived the activity/WS summary path.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("JSONKEY");
        assert!(register_known_secret(&secret));
        let mut value: serde_json::Value =
            serde_json::from_str(&format!(r#"{{"{secret}":"owner","keep":"x"}}"#)).unwrap();
        crate::text::scrub_json_value(&mut value);
        let serialised = value.to_string();
        assert!(!serialised.contains(&secret), "{serialised}");
        assert!(serialised.contains(MASK), "{serialised}");
        // The raw text path already saw the key; keep it pinned too.
        let clean = crate::text::redact_secrets(&format!(r#"{{"{secret}":"owner"}}"#));
        assert!(!clean.contains(&secret), "{clean}");
        clear_known_secrets();
    }

    #[test]
    fn re_registration_touches_the_eviction_order() {
        // SB6-07: the value that is still being re-resolved must not be the
        // next one evicted; a duplicate registration is a "use" of the key.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        for index in 0..MAX_KNOWN_SECRETS {
            register_known_secret(&format!("CANARY_KS_LRU_{index:04}_7f3a9c2e1b5d"));
        }
        let touched = "CANARY_KS_LRU_0000_7f3a9c2e1b5d";
        assert!(!register_known_secret(touched), "already registered");
        register_known_secret("CANARY_KS_LRU_FRESH_7f3a9c2e1b5d");
        assert!(
            redact_known_secrets(&format!("use {touched} now")).is_some(),
            "the touched key is the one that must survive eviction"
        );
        let next_oldest = "CANARY_KS_LRU_0001_7f3a9c2e1b5d";
        assert!(
            redact_known_secrets(&format!("use {next_oldest} now")).is_none(),
            "the least recently registered key must be evicted"
        );
        clear_known_secrets();
    }

    #[test]
    fn short_values_are_not_registered() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        assert!(!register_known_secret("short12"));
        assert!(!register_known_secret("   "));
        assert!(streaming_hold_bytes() >= MIN_STREAM_WINDOW);
        assert!(redact_known_secrets("short12 stays").is_none());
        clear_known_secrets();
    }

    #[test]
    fn debug_output_never_contains_the_value() {
        let secret = unique("DEBUG");
        let known = KnownSecret::new(&secret, 0);
        let printed = format!("{known:?}");
        assert!(printed.contains("<redacted>"), "{printed}");
        assert!(!printed.contains(&secret), "{printed}");
        let registry = Registry {
            values: vec![KnownSecret::new(&secret, 0)],
            ..Registry::default()
        };
        let printed = format!("{registry:?}");
        assert!(!printed.contains(&secret), "{printed}");
    }

    /// dh-1 note: bidi isolate controls count as scrub noise, so a registered
    /// value stuffed with them is still masked whole — an isolate cannot hide
    /// a secret from the exact layer.
    #[test]
    fn bidi_isolates_do_not_hide_a_registered_value() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = format!("CNR7BIDI{}", 1_357_924_680u64);
        assert!(register_known_secret(&secret));
        let hidden: String = secret.chars().map(|c| format!("\u{2066}{c}")).collect();
        let text = format!("token={hidden} end");
        let clean = redact_known_secrets(&text).expect("the isolate-stuffed value must match");
        assert!(clean.contains(MASK), "{clean}");
        assert!(!clean.contains(&secret), "{clean}");
        clear_known_secrets();
    }

    #[test]
    fn home_registration_reads_dotenv_and_api_token() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let dir = tempfile::tempdir().unwrap();
        let env_secret = unique("ENVFILE");
        let telegram_secret = unique("TELEGRAM");
        let token_secret = unique("APITOKEN");
        std::fs::write(
            dir.path().join(ENV_FILE),
            format!("# comment\nexport AUX_KEY_TESTKEY=\"{env_secret}\"\nAUX_TELEGRAM_BOT_TOKEN=\"{telegram_secret}\"\nOTHER=not-registered\n"),
        )
        .unwrap();
        std::fs::write(dir.path().join(API_TOKEN_FILE), format!("{token_secret}\n")).unwrap();
        let registered = register_known_secrets_from_home(dir.path());
        assert!(registered >= 3, "registered {registered}");
        let raw = format!("{env_secret} and {telegram_secret} and {token_secret}");
        let clean = redact_known_secrets(&raw).expect("both must match");
        assert!(!clean.contains(&env_secret), "{clean}");
        assert!(!clean.contains(&telegram_secret), "{clean}");
        assert!(!clean.contains(&token_secret), "{clean}");
        assert!(redact_known_secrets("not-registered").is_none());
        clear_known_secrets();
    }

    #[test]
    fn home_registration_reads_mail_passwords_and_extension_oauth_tokens() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let dir = tempfile::tempdir().unwrap();
        let mail_password = unique("MAILPASS");
        let access = unique("OAUTHACCESS");
        let refresh = unique("OAUTHREFRESH");
        let bundle = format!(
            r#"{{"access_token":"{access}","refresh_token":"{refresh}","expires_at":4102444800,"scopes":["mail"],"token_type":"Bearer"}}"#
        );
        std::fs::write(
            dir.path().join(ENV_FILE),
            format!(
                "AUX_MAIL_PERSONAL={mail_password}\n\
                 EXT_DEMO__OAUTH_TOKENS={bundle}\n\
                 OTHER=not-registered\n"
            ),
        )
        .unwrap();
        let registered = register_known_secrets_from_home(dir.path());
        assert!(registered >= 4, "registered {registered}");

        // The IMAP repro: a server echoes the mailbox password inside quotes.
        let imap = format!("NO [ALERT] wrong password \"{mail_password}\"");
        let clean = redact_known_secrets(&imap).expect("mail password must be registered");
        assert!(clean.contains(MASK), "{clean}");
        assert!(!clean.contains(&mail_password), "{clean}");
        assert!(
            clean.contains('"'),
            "surrounding text must survive: {clean}"
        );

        // The whole token bundle, and the individual tokens a provider error
        // echoes without the JSON around them, are both secrets.
        let clean = redact_known_secrets(&format!("EXT_DEMO__OAUTH_TOKENS={bundle}"))
            .expect("the token bundle must be registered");
        assert!(!clean.contains(&access), "{clean}");
        assert!(!clean.contains(&refresh), "{clean}");
        for token in [&access, &refresh] {
            let clean = redact_known_secrets(&format!("Authorization: Bearer {token}"))
                .unwrap_or_else(|| panic!("token {token:?} must be registered"));
            assert!(clean.contains(MASK), "{clean}");
            assert!(!clean.contains(token), "{clean}");
        }
        assert!(redact_known_secrets("not-registered").is_none());
        clear_known_secrets();
    }

    #[test]
    fn known_secret_names_cover_mail_and_oauth_only() {
        for name in [
            "AUX_KEY_DEEPSEEK",
            "AUX_TELEGRAM_BOT_TOKEN",
            "AUX_MAIL_PERSONAL",
            "AUX_MAIL_WORK_MAIL",
            "EXT_DEMO__OAUTH_TOKENS",
        ] {
            assert!(is_known_secret_name(name), "{name}");
        }
        for name in [
            "AUX_MAILBOX_HOST",
            "AUX_MAIL",
            "EXT_DEMO__CLIENT_SECRET",
            "OAUTH_TOKENS",
            "OTHER",
        ] {
            assert!(!is_known_secret_name(name), "{name}");
        }
    }

    #[test]
    fn unicode_escaped_copies_of_a_known_value_are_redacted() {
        // R7-4: a plain-ASCII value spelled as JSON/JS unicode escapes is the
        // same value; `\uNNNN`, `\UNNNNNNNN` and the braced `\u{NN}` /
        // `\u{NNNN}` forms (both hex cases, contiguous and separated) must
        // all be masked by the whole-buffer pass.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("UNIESC");
        assert!(register_known_secret(&secret));
        let bytes: Vec<u8> = secret.bytes().collect();
        let cases: Vec<(&str, String)> = vec![
            ("u4", bytes.iter().map(|b| format!("\\u{b:04x}")).collect()),
            (
                "u4-upper",
                bytes.iter().map(|b| format!("\\u{b:04X}")).collect(),
            ),
            ("U8", bytes.iter().map(|b| format!("\\U{b:08x}")).collect()),
            (
                "braced2",
                bytes.iter().map(|b| format!("\\u{{{b:02x}}}")).collect(),
            ),
            (
                "braced4",
                bytes.iter().map(|b| format!("\\u{{{b:04x}}}")).collect(),
            ),
            (
                "u4-separated",
                bytes
                    .iter()
                    .map(|b| format!("\\u{b:04x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            (
                "braced-separated",
                bytes
                    .iter()
                    .map(|b| format!("\\u{{{b:02x}}}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            ),
        ];
        for (label, spelling) in cases {
            let text = format!("free text {spelling} inside");
            let clean =
                redact_known_secrets(&text).unwrap_or_else(|| panic!("no match for {label}"));
            assert!(clean.contains(MASK), "{label}: {clean:?}");
            assert!(!clean.contains(&spelling), "{label}: {clean:?}");
        }
        clear_known_secrets();
    }

    /// R8 (1): real NFKC — ligatures, fullwidth, superscripts and decomposed
    /// combining sequences — on both the text and the registered values,
    /// with exact offset mapping back to the original span.
    #[test]
    fn nfkc_compatibility_copies_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let fullwidth = |value: &str| -> String {
            value
                .chars()
                .map(|c| {
                    let cp = c as u32;
                    if (0x21..=0x7E).contains(&cp) {
                        char::from_u32(cp + 0xFEE0).unwrap_or(c)
                    } else {
                        c
                    }
                })
                .collect()
        };
        let pairs: Vec<(&str, String)> = vec![
            // Ligatures (U+FB01 fi, U+FB02 fl, U+FB03 ffi).
            ("officeCNR8alpha987", "of\u{FB01}ceCNR8alpha987".to_string()),
            ("flavorCNR8beta987", "\u{FB02}avorCNR8beta987".to_string()),
            ("officeCNR8gamma987", "o\u{FB03}ceCNR8gamma987".to_string()),
            // Fullwidth letters and digits (U+FF01..U+FF5E).
            ("officeCNR8delta987", fullwidth("officeCNR8delta987")),
            // Superscript digits (U+00B2, U+2079…).
            ("office2CNR8eps987", "office\u{B2}CNR8eps987".to_string()),
            (
                "office9CNR8zeta987",
                "office\u{2079}CNR8zeta987".to_string(),
            ),
            // Decomposed combining sequence vs the composed registered form.
            ("caf\u{E9}CNR8eta987", "cafe\u{301}CNR8eta987".to_string()),
        ];
        for (registered, spelled) in pairs {
            assert!(register_known_secret(registered));
            // The folded scan must reproduce real NFKC for the spelling.
            let (folded, _, _) = fold_nfkc(&spelled);
            assert_eq!(
                folded,
                spelled.nfkc().collect::<String>(),
                "fold_nfkc diverged from NFKC for {spelled:?}"
            );
            let text = format!("free text {spelled} inside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for {spelled:?} (registered {registered:?})"));
            assert!(clean.contains(MASK), "{spelled:?}: {clean:?}");
            assert!(!clean.contains(&spelled), "{spelled:?}: {clean:?}");
        }
        // The reverse direction: a registered compatibility spelling matches
        // the plain text through the value's own NFKC needle.
        for (registered, plain) in [
            ("of\u{FB01}ceCNR8theta987", "officeCNR8theta987"),
            ("cafe\u{301}CNR8iota987", "caf\u{E9}CNR8iota987"),
            ("office\u{B2}CNR8kappa987", "office2CNR8kappa987"),
        ] {
            assert!(register_known_secret(registered));
            let text = format!("free text {plain} inside");
            let clean = redact_known_secrets(&text)
                .unwrap_or_else(|| panic!("no match for {plain:?} (registered {registered:?})"));
            assert!(clean.contains(MASK), "{plain:?}: {clean:?}");
            assert!(!clean.contains(plain), "{plain:?}: {clean:?}");
        }
        clear_known_secrets();
    }

    /// R9 (1): full canonical NFKC — canonical mark reordering and Hangul
    /// Jamo composition — on both the text and the registered value.
    #[test]
    fn nfkc_canonical_reordering_and_hangul_copies_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let pairs = [
            // Conjoining Hangul Jamo vs precomposed syllables.
            (
                "\u{D55C}\u{AE00}CNR9KoreanSecret987",
                "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}CNR9KoreanSecret987",
            ),
            // Canonically reordered combining marks: Å + U+0315.
            (
                "\u{C5}\u{0315}CNR9ZalgoSecret987",
                "A\u{0315}\u{030A}CNR9ZalgoSecret987",
            ),
            // Vietnamese stacked marks, both orders.
            (
                "Vi\u{1EC7}tCNR9VietA987",
                "Vie\u{0302}\u{0323}tCNR9VietA987",
            ),
            (
                "Vi\u{1EC7}tCNR9VietB987",
                "Vie\u{0323}\u{0302}tCNR9VietB987",
            ),
        ];
        for (registered, spelled) in pairs {
            assert!(register_known_secret(registered));
            assert_eq!(
                spelled.nfkc().collect::<String>(),
                registered,
                "the probe spelling must normalise to the registered value"
            );
            let (folded, _, _) = fold_nfkc(spelled);
            assert_eq!(folded, registered, "fold_nfkc diverged for {spelled:?}");
            let text = format!("public {spelled} suffix");
            let clean =
                redact_known_secrets(&text).unwrap_or_else(|| panic!("no match for {spelled:?}"));
            assert!(clean.contains(MASK), "{spelled:?}: {clean:?}");
            assert!(!clean.contains(spelled), "{spelled:?}: {clean:?}");
        }
        clear_known_secrets();
    }

    /// R10 (1): a value longer than the old 512-byte variant cap is
    /// registered and matched (raw and base64); anything over the
    /// registration cap is refused and never claimed as scrubbed.
    #[test]
    fn long_registered_values_are_matched_or_refused() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        // 513 bytes: the raw form used to be dropped by the 512-byte cap.
        let value_513 = "L".repeat(513);
        assert!(register_known_secret(&value_513));
        let text = format!("public {value_513} suffix");
        let clean = redact_known_secrets(&text).expect("the 513-byte value must match");
        assert!(clean.contains(MASK), "no mask in {} bytes", clean.len());
        assert!(!clean.contains(&value_513));
        // Its base64 spelling (684 bytes) is covered too.
        let b64 = STANDARD.encode(value_513.as_bytes());
        assert!(
            b64.len() > 512,
            "the base64 spelling must exceed the old cap"
        );
        let clean =
            redact_known_secrets(&format!("public {b64} suffix")).expect("base64 must match");
        assert!(clean.contains(MASK));
        clear_known_secrets();

        // Over the registration cap: refused, and never claimed as scrubbed.
        let too_long = "L".repeat(MAX_KNOWN_SECRET_LEN + 1);
        assert!(!register_known_secret(&too_long));
        assert!(redact_known_secrets(&format!("public {too_long} suffix")).is_none());
        clear_known_secrets();

        // 256 bytes: the full closure fits the byte budget and covers
        // base64-of-lower-hex (684 bytes) and base64-of-colon-hex.
        let value_256 = "L".repeat(256);
        assert!(register_known_secret(&value_256));
        assert!(
            !registry_oversized(),
            "a 256-byte secret must fit the variant budget"
        );
        let hex = hex_encode(&value_256, false);
        let b64_of_hex = STANDARD.encode(hex.as_bytes());
        assert!(b64_of_hex.len() > 512, "the repro spelling is 684 bytes");
        let clean =
            redact_known_secrets(&format!("public {b64_of_hex} suffix")).unwrap_or_else(|| {
                panic!(
                    "base64-of-lower-hex must match ({} bytes)",
                    b64_of_hex.len()
                )
            });
        assert!(clean.contains(MASK));
        let colon = hex_separated(&value_256, ":", false);
        let b64_of_colon = STANDARD.encode(colon.as_bytes());
        let clean = redact_known_secrets(&format!("public {b64_of_colon} suffix"))
            .unwrap_or_else(|| panic!("base64-of-colon-hex must match"));
        assert!(clean.contains(MASK));
        clear_known_secrets();
        assert!(!registry_oversized());
    }

    /// R10 (2): a value whose closure exceeds the budget is still registered
    /// (its raw form matches) but flags the registry oversized, so live
    /// streams fail closed instead of silently missing spellings.
    #[test]
    fn oversized_closures_register_and_flag_fail_closed() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let value = "K".repeat(1024);
        assert!(register_known_secret(&value));
        assert!(
            registry_oversized(),
            "a 1024-byte value's closure exceeds the budget"
        );
        let clean =
            redact_known_secrets(&format!("public {value} suffix")).expect("the raw must match");
        assert!(clean.contains(MASK));
        clear_known_secrets();
        assert!(!registry_oversized());

        // The documented threshold (GLM-P3): 409 bytes stays covered, 410
        // bytes cannot (the `0x`-of-hex composition passes the 4096-byte
        // needle cap there), so the registry fails every stream closed.
        assert!(register_known_secret(&"K".repeat(409)));
        assert!(
            !registry_oversized(),
            "409 bytes must stay under the closure threshold"
        );
        clear_known_secrets();
        assert!(register_known_secret(&"K".repeat(410)));
        assert!(
            registry_oversized(),
            "410 bytes is the documented closure threshold"
        );
        clear_known_secrets();
        assert!(!registry_oversized());
    }

    /// R9 (2): the depth-2 composition closure — every pair of transforms
    /// applied to a registered value is masked.
    #[test]
    fn composed_transform_pairs_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = "CNR9~Secret~987";
        assert!(register_known_secret(secret));
        let mut checked = 0usize;
        for &first in TRANSFORMS.iter() {
            let Some(step1) = apply_transform(first, secret) else {
                continue;
            };
            for &second in TRANSFORMS.iter() {
                let Some(step2) = apply_transform(second, &step1) else {
                    continue;
                };
                // The registration budget drops spellings longer than
                // `MAX_VARIANT_LEN` (the decoded scan still covers hex-family
                // spellings); the pair sweep follows the same budget.
                if step2.len() > MAX_VARIANT_LEN {
                    continue;
                }
                checked += 1;
                let text = format!("public {step2} suffix");
                let clean = redact_known_secrets(&text)
                    .unwrap_or_else(|| panic!("no match for the composed spelling {step2:?}"));
                assert!(clean.contains(MASK), "{step2:?}: {clean:?}");
                assert!(!clean.contains(&step2), "{step2:?}: {clean:?}");
            }
        }
        assert!(
            checked > 100,
            "the pair sweep must cover many pairs: {checked}"
        );
        clear_known_secrets();
    }

    /// R8 (2): JSON surrogate-pair escapes of a non-BMP character in a
    /// registered value, in every spelling the JSON/JS world uses.
    #[test]
    fn surrogate_pair_escaped_copies_of_a_known_value_are_redacted() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = format!("CNR8{}Surrogate987", '\u{1F600}');
        assert!(register_known_secret(&secret));
        let all_escaped: String = secret
            .chars()
            .map(|c| {
                let code = c as u32;
                if code > 0xFFFF {
                    format!(
                        "\\u{:04X}\\u{:04X}",
                        surrogate_pair(code).0,
                        surrogate_pair(code).1
                    )
                } else {
                    format!("\\u{code:04X}")
                }
            })
            .collect();
        let all_escaped_lower: String = secret
            .chars()
            .map(|c| {
                let code = c as u32;
                if code > 0xFFFF {
                    format!(
                        "\\u{:04x}\\u{:04x}",
                        surrogate_pair(code).0,
                        surrogate_pair(code).1
                    )
                } else {
                    format!("\\u{code:04x}")
                }
            })
            .collect();
        let cases = [
            ("mixed-upper", "CNR8\\uD83D\\uDE00Surrogate987".to_string()),
            ("mixed-lower", "CNR8\\ud83d\\ude00Surrogate987".to_string()),
            ("U8", "CNR8\\U0001F600Surrogate987".to_string()),
            ("braced", "CNR8\\u{1F600}Surrogate987".to_string()),
            ("all-escaped-upper", all_escaped),
            ("all-escaped-lower", all_escaped_lower),
        ];
        for (label, spelling) in cases {
            let text = format!("free text {spelling} inside");
            let clean =
                redact_known_secrets(&text).unwrap_or_else(|| panic!("no match for {label}"));
            assert!(clean.contains(MASK), "{label}: {clean:?}");
            assert!(!clean.contains(&spelling), "{label}: {clean:?}");
        }
        clear_known_secrets();
    }

    #[test]
    fn fullwidth_copies_of_a_known_value_are_redacted() {
        // R7 P3: NFKC-compatible fullwidth letters/digits are the same value
        // to a human and to any NFKC normaliser; the whole-buffer pass folds
        // them and masks the original span.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = unique("NFKC");
        assert!(register_known_secret(&secret));
        let fullwidth: String = secret
            .chars()
            .map(|c| {
                let cp = c as u32;
                if (0x21..=0x7E).contains(&cp) {
                    char::from_u32(cp + 0xFEE0).unwrap_or(c)
                } else {
                    c
                }
            })
            .collect();
        let text = format!("free text {fullwidth} inside");
        let clean = redact_known_secrets(&text).expect("the fullwidth value must match");
        assert!(clean.contains(MASK), "{clean:?}");
        assert!(!clean.contains(&fullwidth), "{clean:?}");

        // A fullwidth colon-hex dump folds to the ASCII dump and decodes.
        let dump: String = secret
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let fullwidth_dump: String = dump
            .chars()
            .map(|c| char::from_u32(c as u32 + 0xFEE0).unwrap_or(c))
            .collect();
        let text = format!("dump {fullwidth_dump} end");
        let clean = redact_known_secrets(&text).expect("the fullwidth dump must match");
        assert!(clean.contains(MASK), "{clean:?}");
        assert!(!clean.contains(&fullwidth_dump), "{clean:?}");
        clear_known_secrets();
    }

    #[test]
    fn pinned_secrets_survive_eviction_and_unpin_trims() {
        // R7-1: a value a live stream relies on must not be evicted by the
        // LRU cap; releasing the pin trims the registry back to the cap.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let live = unique("PINNED");
        assert!(register_known_secret(&live));
        let epoch = pin_known_secrets();
        for index in 0..MAX_KNOWN_SECRETS + 8 {
            register_known_secret(&format!("CANARY_KS_PIN_{index:04}_7f3a9c2e1b5d"));
        }
        assert!(
            redact_known_secrets(&format!("use {live} now")).is_some(),
            "a pinned value must survive cap pressure"
        );
        assert!(
            read_registry().values.len() <= MAX_KNOWN_SECRETS,
            "unpinned values must still be evicted at the cap"
        );
        // Pin everything, then the registry may exceed the cap temporarily.
        let second = pin_known_secrets();
        for index in 0..8 {
            register_known_secret(&format!("CANARY_KS_PINB_{index:04}_7f3a9c2e1b5d"));
        }
        assert!(
            read_registry().values.len() > MAX_KNOWN_SECRETS,
            "an all-pinned registry may exceed the cap until the streams end"
        );
        unpin_known_secrets(second);
        assert_eq!(
            read_registry().values.len(),
            MAX_KNOWN_SECRETS,
            "releasing a pin trims the registry back to the cap"
        );
        assert!(
            redact_known_secrets(&format!("use {live} now")).is_some(),
            "the first pin still protects its value"
        );
        unpin_known_secrets(epoch);
        clear_known_secrets();
    }

    /// R8 (3): with every value pinned, the registry grows to the hard
    /// ceiling and then refuses new values (streams fail closed) instead of
    /// evicting a pinned value. The pinned target survives.
    #[test]
    fn all_pinned_registry_refuses_new_values_at_the_hard_ceiling() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let target = unique("PINHARD");
        assert!(register_known_secret(&target));
        for index in 0..MAX_KNOWN_SECRETS - 1 {
            register_known_secret(&format!("CANARY_KS_HARDFILL_{index:04}_7f3a9c2e1b5d"));
        }
        assert_eq!(read_registry().values.len(), MAX_KNOWN_SECRETS);
        let mut epochs = vec![pin_known_secrets()];
        // Grow to the hard ceiling with every value pinned.
        for index in 0..MAX_KNOWN_SECRETS_HARD {
            if registry_saturated() {
                break;
            }
            register_known_secret(&format!("CANARY_KS_HARDGROW_{index:04}_7f3a9c2e1b5d"));
            epochs.push(pin_known_secrets());
        }
        assert!(
            registry_saturated(),
            "the registry must report saturation at the hard ceiling"
        );
        assert_eq!(read_registry().values.len(), MAX_KNOWN_SECRETS_HARD);
        // A new value is refused rather than evicting a pinned one.
        assert!(
            !register_known_secret("CANARY_KS_HARDOVER_7f3a9c2e1b5d"),
            "a new value must be refused at the hard ceiling"
        );
        assert!(
            redact_known_secrets(&format!("use {target} now")).is_some(),
            "the pinned target must never be evicted"
        );
        assert_eq!(
            read_registry().values.len(),
            MAX_KNOWN_SECRETS_HARD,
            "a refusal must not grow the registry further"
        );
        for epoch in epochs {
            unpin_known_secrets(epoch);
        }
        assert!(
            read_registry().values.len() <= MAX_KNOWN_SECRETS,
            "unpinning must trim back to the cap"
        );
        assert!(!registry_saturated());
        clear_known_secrets();
    }

    #[test]
    fn registration_never_grows_past_the_cap() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        for index in 0..MAX_KNOWN_SECRETS + 8 {
            let value = format!("CANARY_KS_CAP_{index:04}_7f3a9c2e1b5d");
            register_known_secret(&value);
        }
        let registry = read_registry();
        assert_eq!(registry.values.len(), MAX_KNOWN_SECRETS);
        drop(registry);
        // The newest registration survived the eviction of the oldest.
        let newest = format!("CANARY_KS_CAP_{:04}_7f3a9c2e1b5d", MAX_KNOWN_SECRETS + 7);
        assert!(
            redact_known_secrets(&format!("use {newest} now")).is_some(),
            "the newest key must still register at the cap"
        );
        let oldest = "CANARY_KS_CAP_0000_7f3a9c2e1b5d";
        assert!(
            redact_known_secrets(&format!("use {oldest} now")).is_none(),
            "the evicted oldest key must not match"
        );
        clear_known_secrets();
    }

    #[test]
    #[ignore = "timing test: run alone with --ignored --test-threads=1"]
    fn known_secret_layer_is_linear_at_one_megabyte() {
        // H-04/L-1: the exact-value layer runs first on every scrub; with a
        // realistic one-key registry it must stay linear at 1 MiB for the
        // raw value, its split form and the ordinary adversarial shapes.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let secret = format!("sk-{}", "CANARYKSCOST7f3a9c2e1b5d");
        assert!(register_known_secret(&secret));
        const SIZE: usize = 1024 * 1024;
        let half = secret.len() / 2;
        let dump_unit = xxd_dump(&secret);
        let shapes = |size: usize| -> Vec<(&'static str, String)> {
            let known_dump = dump_unit.repeat(size / dump_unit.len().max(1));
            vec![
                (
                    "known-raw",
                    format!("prefix {secret} suffix ").repeat(size / 40),
                ),
                (
                    "known-split",
                    format!("prefix {}\n{} suffix ", &secret[..half], &secret[half..])
                        .repeat(size / 40),
                ),
                ("long-line", "a".repeat(size)),
                (
                    "json-escaped-quotes",
                    "{\"a\":\"b\\\"c\"},".repeat(size / 15),
                ),
                (
                    "bracket-values",
                    "api_key=(abcdef123456) ".repeat(size / 23),
                ),
                (
                    "sibling-pairs",
                    "{\"name\":\"api_key\",\"value\":\"abcdef123456\"},".repeat(size / 45),
                ),
                // --- round 6: the hex spellings stay linear at 1 MiB ---
                (
                    "hex-separated",
                    "73 62 36 6b 37 58 71 32 6d 4e 76 52 \n".repeat(size / 35),
                ),
                (
                    "escaped-hex",
                    "\\x73\\x62\\x36\\x6b\\x37\\x58\\x71\\x32".repeat(size / 32),
                ),
                (
                    "xxd-dump",
                    "00000000: 7362 366b 3758 7132 6d4e 7652 7434 4c70  sb6k7Xq2mNvRt4Lp\n"
                        .repeat(size / 57),
                ),
                ("xxd-dump-of-known", known_dump),
            ]
        };
        // Linear means 4x the input costs about 4x the time; quadratic costs
        // 16x. Compare each shape at n and 4n (best of 3 runs each) instead of
        // a wall-clock budget, which flakes on a loaded machine. The hang guard
        // is only for a true blow-up.
        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(30);
        let best_of_three = |label: &str, text: &str| -> std::time::Duration {
            (0..3)
                .map(|_| {
                    let started = std::time::Instant::now();
                    let _ = crate::text::redact_secrets(text);
                    let elapsed = started.elapsed();
                    assert!(
                        elapsed < HANG_GUARD,
                        "{label}: {elapsed:?} on {} bytes (hang guard {HANG_GUARD:?})",
                        text.len()
                    );
                    elapsed
                })
                .min()
                .unwrap_or_default()
        };
        let floor = std::time::Duration::from_millis(1);
        for ((label, small), (_, large)) in shapes(SIZE / 4).into_iter().zip(shapes(SIZE)) {
            let t_small = best_of_three(label, &small);
            let t_large = best_of_three(label, &large);
            assert!(
                t_large <= t_small.max(floor) * 12,
                "{label}: {t_large:?} on {} bytes vs {t_small:?} on {} bytes (4x input must cost under 12x time)",
                large.len(),
                small.len()
            );
        }
        clear_known_secrets();
    }

    /// The streaming cut contract: for every split of a pattern-shaped
    /// secret, `redact_secrets(raw[..cut])` is a byte-prefix of
    /// `redact_secrets(raw)`, so a writer that emits the prefix now and the
    /// remainder later streams exactly the whole-buffer scrub — and never a
    /// half-published token.
    #[test]
    fn stream_prefix_cut_contract_holds_at_every_split() {
        // Pattern-based (no registry mutation): a vendor token split at every
        // byte boundary inside two windows of filler.
        let token = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let filler = "The quick brown fox jumps over the lazy dog. ".repeat(24);
        for split in 1..token.len() {
            let mut raw = String::new();
            raw.push_str(&filler);
            raw.push_str(&token[..split]);
            let cut = stream_prefix_cut(&raw);
            let whole_prefix = crate::text::redact_secrets(&raw[..cut]);
            raw.push_str(&token[split..]);
            raw.push_str(&filler);
            let whole = crate::text::redact_secrets(&raw);
            assert!(
                whole.starts_with(whole_prefix.as_str()),
                "split {split}: the early cut is not a prefix of the whole scrub"
            );
            assert!(
                !whole_prefix.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
                "split {split}: a half token was published"
            );
            assert!(
                !whole.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
                "split {split}: the token survived the whole-buffer scrub"
            );
        }
    }

    /// A streaming writer that re-cuts as text arrives and finishes with the
    /// whole-buffer remainder produces exactly the whole-buffer scrub.
    #[test]
    fn stream_prefix_cut_streaming_matches_the_whole_buffer_scrub() {
        let token = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let raw = format!("{}token={}{}", "x".repeat(600), token, "y".repeat(600));
        let mut emitted = String::new();
        let mut cut = 0usize;
        for end in 1..=raw.len() {
            if !raw.is_char_boundary(end) {
                continue;
            }
            let next = stream_prefix_cut(&raw[..end]);
            if next > cut {
                emitted.push_str(&crate::text::redact_secrets(&raw[cut..next]));
                cut = next;
            }
        }
        // Final flush: the remainder of the whole-buffer scrub.
        let whole = crate::text::redact_secrets(&raw);
        assert!(whole.starts_with(emitted.as_str()));
        emitted.push_str(&whole[emitted.len()..]);
        assert_eq!(emitted, whole);
        assert!(!emitted.contains(token), "{emitted}");
    }
}
