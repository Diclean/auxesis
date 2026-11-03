//! Text hygiene for untrusted content entering the model context or the
//! terminal.
//!
//! Tool outputs, provider errors and model text are all *external* input:
//! they can contain ANSI escapes, bidi overrides and zero-width characters
//! that spoof what a human sees, and they can be arbitrarily large. These
//! helpers strip the invisible characters and cap the size.
//!
//! [`sanitize_error_detail`] and [`scrub_external_preview`] are the shared
//! presentation scrubbers: the daemon API, the CLI and the app render
//! upstream error strings through them, so no transport error (which may be
//! attacker-influenced) can forge terminal output or carry key-shaped
//! strings.

use std::path::Path;
use std::sync::OnceLock;

pub use kernel_core::text::sanitize_text;
use kernel_core::text::truncate_chars;
use kernel_privacy::safetext::{Detector, StandardDetector};
use kernel_privacy::EntityKind;

/// Marker that replaces one redacted value. The key, its separator and every
/// structural byte around the value are re-emitted unchanged: redaction
/// replaces the value only.
pub(crate) const MASK: &str = "<redacted>";

/// Bounded window (bytes) the pair scanner may skip between a separator and
/// its value: spaces, tabs, line breaks, indentation and one shell line
/// continuation (B3-01). Bounded so the skip can never go quadratic.
pub(crate) const PAIR_SKIP_LIMIT: usize = 256;

/// Bounded window (bytes) the quoted-value scan looks across for a closing
/// quote, so a value broken over lines is one value without ever rescanning
/// the document (B3-01/B3-02).
pub(crate) const QUOTED_SCAN_LIMIT: usize = 1024;

/// Scrub an upstream error string before it is echoed to the owner.
///
/// Deliberately conservative: control and invisible characters are stripped
/// (a message must never contain ANSI escapes or bidi tricks), the Auxesis
/// `home` path is replaced by `<home>`, every documented **plain-text**
/// secret shape is redacted by [`redact_secrets`] (defense in depth: no key
/// material in an error), and the result is collapsed to one line and capped
/// at `max_chars` characters. Pattern redaction cannot see values that are
/// base64/hex/line-split before they reach the text; see [`redact_secrets`].
pub fn sanitize_error_detail(home: &Path, text: &str, max_chars: usize) -> String {
    // Known values first: redact before the cap, so a truncation can never
    // leave half a resolved key in the message.
    let known = super::scrub::redact_known_secrets(text);
    let text: &str = known.as_deref().unwrap_or(text);
    // Normalise next: an ANSI sequence between a name and its separator must
    // be dropped as a unit *before* the plain sanitiser leaves its residue
    // (`api_key[0m=…`); L0 in `redact_secrets` would arrive too late.
    let normalised = normalise_for_scrub(text);
    let cleaned = sanitize_external_text(&normalised, max_chars * 4);
    let home = home.display().to_string();
    let cleaned = if home.is_empty() {
        cleaned
    } else {
        cleaned.replace(&home, "<home>")
    };
    let cleaned = redact_secrets(&cleaned);
    let collapsed: String = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&collapsed, max_chars)
}

/// Scrub one tool-visible preview string (arguments, result): sanitize
/// control/invisible characters, replace the Auxesis home path with
/// `<home>`, redact every documented secret shape via [`redact_secrets`],
/// and cap the result.
///
/// Same transformations as [`sanitize_error_detail`] minus the one-line
/// collapse: a preview may legitimately span lines (a command, a diff).
pub fn scrub_external_preview(home: &Path, text: &str, max_bytes: usize) -> String {
    // Known values first (same reason as `sanitize_error_detail`): a
    // truncation must never cut a resolved key before it is redacted.
    let known = super::scrub::redact_known_secrets(text);
    let base: &str = known.as_deref().unwrap_or(text);
    // If the heuristic layers find nothing to redact either, nothing in this
    // text hides a secret: keep the bytes that are content, including the
    // bidi isolate controls the scanning normaliser strips (dh-1 fidelity
    // note). Anything else (ANSI, other invisibles) is still sanitised.
    let redacted = redact_secrets(base);
    if redacted == base {
        let cleaned = sanitize_external_text_keep_isolates(base, max_bytes);
        let cleaned = replace_home(cleaned, home);
        return redact_secrets(&cleaned);
    }
    // Something was redacted: the normalised/masked text is the
    // authoritative one, and the same ordering as before applies (mask
    // before the cap so a truncation cannot cut a key into view; scrub again
    // after the cap for a secret the head/tail cut may have completed).
    let cleaned = sanitize_external_text(&redacted, max_bytes);
    let cleaned = replace_home(cleaned, home);
    redact_secrets(&cleaned)
}

/// The most characters of a candidate title the detector scans. Display caps
/// smaller than this (the 60-character chat title) run after detection.
const TITLE_SCAN_CHARS: usize = 400;

/// The most characters a scrubbed title returns. Detection has already seen
/// the full 400-character scan, so this display cap cannot expose a prefix.
const TITLE_RETURN_CHARS: usize = 200;

/// Byte cap after labels and sanitising: 400 characters are at most 1600 UTF-8
/// bytes, and the labels add a little.
const TITLE_SCRUB_BYTES: usize = 4096;

/// Written instead of a title when detection itself fails: a title is display
/// text, so the failure is closed, never the raw line.
const TITLE_HIDDEN: &str = "[title hidden]";

/// Written instead of display text when detection itself fails.
const DISPLAY_HIDDEN: &str = "[content hidden]";

/// The one detector shared by every scrub. It is the same standard set a
/// Private-mode gate runs: e-mail, phone, IBAN, payment card, national IDs,
/// health terms, secrets and the rest of the deterministic registry.
fn title_detector() -> &'static StandardDetector {
    static DETECTOR: OnceLock<StandardDetector> = OnceLock::new();
    DETECTOR.get_or_init(StandardDetector::new)
}

/// The short neutral label a title shows in place of one detected value, or
/// `None` when the value stays readable: the owner's rule keeps every name
/// visible.
fn title_label(kind: EntityKind) -> Option<&'static str> {
    Some(match kind {
        EntityKind::Email => "[e-mail]",
        EntityKind::Phone => "[phone]",
        EntityKind::Iban => "[IBAN]",
        EntityKind::CreditCard => "[card]",
        // A link or a bare IP is not one of the PII classes a title or a
        // preview hides; a value inside one (an e-mail in a URL) is still its
        // own span and is labelled above it.
        EntityKind::IpV4 | EntityKind::Url => return None,
        EntityKind::FrNir
        | EntityKind::FrSiret
        | EntityKind::HuTaj
        | EntityKind::HuTaxId
        | EntityKind::ZaId
        | EntityKind::UkNino
        | EntityKind::PassportMrz
        | EntityKind::NationalId => "[ID]",
        EntityKind::FrSiren | EntityKind::FrVat => "[company ID]",
        EntityKind::Address => "[address]",
        EntityKind::DateOfBirth => "[date of birth]",
        EntityKind::Health => "[health]",
        EntityKind::Religion => "[religion]",
        EntityKind::SexualOrientation => "[orientation]",
        EntityKind::Union => "[union]",
        EntityKind::Ethnicity => "[ethnicity]",
        EntityKind::Secret => "[secret]",
        EntityKind::Person | EntityKind::Organization => return None,
    })
}

/// Every detected non-name value in `text` replaced by its neutral label.
/// `None` means detection failed or returned a malformed span: callers fail
/// closed with their own fixed text. `include_secret` is off for display
/// text that already ran the secret scrubber: keeping its `<redacted>` marker
/// (and its established false positives) beats relabelling it `[secret]`.
fn label_detected(text: &str, include_secret: bool) -> Option<String> {
    let mut spans = title_detector().detect(text).ok()?;
    spans.sort_by_key(|span| (span.start, span.end));
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for span in spans {
        if span.kind == EntityKind::Secret && !include_secret {
            continue;
        }
        let Some(label) = title_label(span.kind) else {
            continue;
        };
        if span.start < copied
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            return None;
        }
        out.push_str(&text[copied..span.start]);
        out.push_str(label);
        copied = span.end;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

/// The title line of `text` with every detected value replaced by its short
/// neutral label: the first line, scanned up to 400 characters **before**
/// detection, then capped at 200 characters for display.
///
/// The detector is the same set Private mode runs, so an e-mail, phone, IBAN,
/// card, national ID, health term or secret typed as the first line never
/// becomes a chat title. Names are left visible on purpose (owner rule).
/// Detection failure yields [`TITLE_HIDDEN`], never the raw line. If the scan
/// cap would cut through a run with no whitespace, the whole run is dropped and
/// an ellipsis marks the cut: a partial candidate is never detected as text.
pub fn scrub_title(text: &str) -> String {
    let first = text.lines().next().unwrap_or("").trim();
    let chars: Vec<char> = first.chars().collect();
    let cut = chars.len() > TITLE_SCAN_CHARS;
    let mut scan: String = chars.iter().take(TITLE_SCAN_CHARS).collect();
    if cut && !scan.chars().last().is_some_and(char::is_whitespace) {
        // The cap fell inside a non-whitespace run. Drop the run: its start
        // may be a value whose tail (the detector would need) is past the cap.
        match scan.rfind(char::is_whitespace) {
            Some(at) => scan.truncate(at),
            None => scan.clear(),
        }
    }
    // Detect on the bytes a reader would see: an ANSI sequence must not split
    // an address the sanitiser would later join back together.
    let bounded = sanitize_external_text_keep_isolates(&scan, TITLE_SCRUB_BYTES);
    let mut out = if bounded.is_empty() {
        String::new()
    } else {
        label_detected(&bounded, true).unwrap_or_else(|| TITLE_HIDDEN.to_string())
    };
    if cut {
        out.push('…');
    }
    truncate_chars(&out, TITLE_RETURN_CHARS)
}

/// Full-detector scrub for display text that is not a single title: every
/// detected non-name value gets its neutral label before the caller collapses
/// lines or caps the result. Secret spans are left to the caller's established
/// secret scrubber, which keeps its `<redacted>` marker. Detection failure
/// yields [`DISPLAY_HIDDEN`].
pub fn scrub_display_text(text: &str, max_bytes: usize) -> String {
    let clean = sanitize_external_text_keep_isolates(text, max_bytes);
    match label_detected(&clean, false) {
        Some(out) => redact_secrets(&out),
        None => DISPLAY_HIDDEN.to_string(),
    }
}

/// Redact every documented secret shape from `text`.
///
/// Security-review round 3 turned this from one tokenizer into **composed layers**
/// behind this single entry point, because the same area failed three rounds
/// in a row: every caller (API previews, error details, the WS frame
/// sanitizer, the run-summary scrub and the daemon log writer) gets all of
/// them without knowing about them.
///
/// - **L-1 known values.** Exact-value redaction of the secrets this process
///   has resolved (`AUX_KEY_*` from `.env`/environment, the API token, every
///   provider key the engine loads), plus their common transforms
///   (base64, percent-encoded, JSON-escaped, whitespace/zero-width-split).
///   `crate::scrub` owns the registry; the scan is linear and off — zero
///   allocation — when nothing is registered. This is the layer that catches
///   a key with no name in front of it; the shape layers remain the fallback
///   for unknown secrets.
/// - **L0 normalise.** Secret-adjacent separator lookalikes (`＝`, `：` and
///   the small forms) are folded to their ASCII separators, and every
///   control/invisible/format character (U+200B–U+200F, U+2060, U+FEFF,
///   soft hyphen, bidi controls, …) is stripped. `token\u{200b}=…`,
///   `api_key＝…` and `api_key：…` are therefore the same pair as their ASCII
///   spelling *before* any scan runs (B3-03, B3-04). The fold is
///   context-sensitive: only a lookalike separator directly after a
///   credential-looking name is rewritten, so ordinary prose, curly quotes,
///   CJK punctuation and fullwidth letters come out byte-identical
///   (B5-07/H-05).
/// - **L1 structured.** When the text — or a balanced JSON substring inside
///   it — parses with `serde_json`, the value tree is walked: the value of
///   any key whose normalised name names a credential is replaced, values
///   that are themselves JSON strings are scrubbed recursively, and the
///   region is re-serialised. Pretty-printed JSON, escaped quotes, nesting
///   and JSON-inside-JSON cannot hide a key from a parser (B3-01, B3-02).
///   [`scrub_json_value`] exposes the same walk to callers that hold a
///   `serde_json::Value` *before* it is re-serialised (activity/WS summaries).
///   A region with nothing to redact is returned **byte for byte** (B4-01):
///   whitespace, escape spelling, duplicate keys, key order and every number
///   lexeme survive untouched. Only a region in which something *was*
///   redacted is re-serialised (compactly, keys in input order via
///   `preserve_order`, numbers exact via `arbitrary_precision`).
/// - **L2 tokenizer.** The single-pass, linear-time tokenizer from round 2,
///   extended with multi-line pair values (bounded window), `\"` escapes,
///   `;`-separated cookie jars, percent-encoded URL schemes and the stricter
///   `plausible_token` gates.
///
/// The layer order matters: normalising first means L1 can parse JSON that
/// carries invisible or fullwidth punctuation, and the parser runs before
/// the tokenizer so escapes (`{\"api_key\":…}`) are resolved on real keys.
///
/// The tokenizer recognises, in any position:
///
/// - PEM blocks (`-----BEGIN <label>-----`, label case-insensitive) whose
///   label contains `PRIVATE KEY`, through the matching `-----END` marker (or
///   to the end of the text when it is missing), and PuTTY/OpenSSH new-format
///   keys (`PuTTY-User-Key-File-…`, no `BEGIN` marker);
/// - URL/URI userinfo credentials (`scheme://user:pass@host`, any scheme,
///   `redis://:pass@`, `mongodb+srv://…`, and the percent-encoded
///   `scheme%3A%2F%2Fuser:pass@host` spelling): the credential part is
///   replaced, the scheme and host stay readable;
/// - HTTP header lines: `authorization`/`proxy-authorization` values that
///   look like opaque secrets, and the whole value of `cookie`, `set-cookie`,
///   `x-api-key`, `x-auth-token`, `x-hub-signature*`, `x-amz-security-token`,
///   `x-goog-api-key` and `x-access-token` — short, low-entropy cookie values
///   included;
/// - key/value pairs separated by `=`, `:`, `:=` or their percent-encoded
///   forms `%3D`/`%3A`, quoted (`{"api_key":"…"}`, `"k": "v"`) or unquoted,
///   with an optional line break and indentation between the separator and
///   the value, with vendor-style names split on `_`/`-`/`.` (`DB_PASSWORD`,
///   `client_secret`, `GPG_PASSPHRASE`, `X-Api-Key`, …), the daemon's own
///   `AUX_KEY_…` env shape, cookie-jar names (`session`, `sid`, `jsessionid`,
///   `csrftoken`, …) and URL-shaped names (`*_URL`, `*_URI`,
///   `*_WEBHOOK_URL`);
/// - vendor-prefixed tokens (`sk-`, `ghp_`, `github_pat_`, `glpat-`, `AIza`,
///   `AKIA…`, `xox…-`, `npm_`, …), matched only at the start of a token run so
///   `task-sk-1234` and `disk-sk-usage` stay readable;
/// - `Bearer`/`Basic` scheme values and `curl -u`/`--user`/`--password`
///   values that look like opaque credentials;
/// - `eyJ…` JWTs (three dot-separated segments).
///
/// Value shape gates keep ordinary text intact: a secret-named assignment is
/// redacted when its value is token-shaped (digits, mixed case, a long opaque
/// run or a quoted passphrase) — so `public_key_sha256 = 9f2a1b3c`,
/// `key = "abcdefghijkl"` and `let token = parse(input);` survive — and the
/// strongest components (`password`, `token`, `secret`, …) use a looser gate
/// than the weak `key` component. Hash/checksum/fingerprint names without a
/// strong component (`public_key_sha256`) are never treated as credentials, a
/// `*_id`/`*_uuid` name is an identifier, and an all-digit epoch, a UUID or a
/// CamelCase type name is not a secret by shape alone (B3-07). A match is
/// re-emitted with its original spelling, never rewritten to a constant name.
///
/// This is a *pattern* redactor: values that are base64-, hex- or
/// newline-encoded before they reach the text are out of scope, and no
/// caller may claim more than that. The API response body is the contract.
///
/// B4-01: a text with nothing to redact is returned **byte for byte**
/// (whitespace, escape spelling, duplicate keys, key order and number
/// lexemes included). Only a JSON region in which something was redacted is
/// re-serialised, and then it keeps key order and exact number lexemes.
pub fn redact_secrets(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    // L-1: exact-value redaction of the secrets this process knows. This is
    // the precise layer: it needs no name or shape next to the value, so a
    // key the daemon itself resolved can never survive in prose, a tool
    // argument or an encoded copy. `None` (empty registry or no match) keeps
    // the original bytes with no allocation; the heuristic layers below stay
    // the fallback for values this process has never seen.
    let known = super::scrub::redact_known_secrets(text);
    let had_known = known.is_some();
    let original: &str = known.as_deref().unwrap_or(text);
    // L0: one normalised alphabet for every layer below.
    let normalised = normalise_for_scrub(original);
    if normalised.is_empty() {
        // Only invisible/space characters: keep the isolates, drop the rest.
        return kernel_core::text::sanitize_text_keep_bidi_isolates(&strip_ansi(original));
    }
    // L1: structured JSON, whole document first, then balanced substrings.
    let structured = scrub_json_document(&normalised).or_else(|| scrub_embedded_json(&normalised));
    let structured_changed = structured
        .as_deref()
        .is_some_and(|structured| structured != normalised);
    let base = structured.as_deref().unwrap_or(&normalised);
    // L2: the linear tokenizer, on the structured result.
    let out = Redactor {
        text: base,
        bytes: base.as_bytes(),
        out: String::with_capacity(base.len()),
        copied: 0,
        cursor: 0,
    }
    .run();
    if had_known || structured_changed || out != base {
        out
    } else {
        // Nothing needed redaction: keep the bytes, including the bidi
        // isolate controls the L0 scan strips (dh-1 fidelity note). ANSI and
        // the other control/invisible characters still go; only the four
        // isolates are content rather than spoofing scaffolding.
        kernel_core::text::sanitize_text_keep_bidi_isolates(&strip_ansi(original))
    }
}

/// What an echo of a value may show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchoState {
    /// The value is not secret-shaped.
    Clean,
    /// The value is secret-shaped, raw or through a decoded copy.
    Secret,
    /// The decoder cannot settle the value inside its work budget.
    Unstable,
}

/// The raw value and every percent-decoded copy of it, classified.
///
/// The caller decides what to render: [`EchoState::Secret`] as
/// `<redacted>`/`<id>`, [`EchoState::Unstable`] as `[hidden]`. A provider id
/// is a name and a lookup handle, so a key-shaped name is refused rather than
/// stored or echoed.
pub fn classify_echo(text: &str) -> EchoState {
    if redact_secrets(text) != text {
        return EchoState::Secret;
    }
    // The scrubber has read the value once already: that read is charged to
    // the budget too.
    decoded_copy_state(text, text.len(), |copy| redact_secrets(copy) != copy)
}

/// True when `text` is secret-shaped, raw or through any decoded copy.
///
/// This is the one detector the provider layer and the store migrations use.
pub fn is_secret_shaped(text: &str) -> bool {
    !matches!(classify_echo(text), EchoState::Clean)
}

/// 32 escape layers: `%73k-…`, `%2573k-…` and `%25252573k-…` are one key.
const MAX_DECODE_ROUNDS: usize = 32;

/// The work budget of one value: every byte the scrubber or the decoder
/// reads is charged, at most 66 × the input and never over 4 MiB.
const MAX_REDACT_WORK: usize = 4 * 1024 * 1024;

/// How a percent-decoded copy of `text` reads. One escape layer per round,
/// only the current copy kept, every byte read charged to the budget. A value
/// still changing when the budget or [`MAX_DECODE_ROUNDS`] runs out is
/// [`EchoState::Unstable`], because it cannot be shown safely.
fn decoded_copy_state(
    text: &str,
    mut spent: usize,
    secret_shaped: impl Fn(&str) -> bool,
) -> EchoState {
    let budget = text.len().saturating_mul(66).min(MAX_REDACT_WORK);
    let mut current = text.to_string();
    for _ in 0..MAX_DECODE_ROUNDS {
        // A round that does not fit the budget is never started.
        if spent.saturating_add(current.len()) > budget {
            return EchoState::Unstable;
        }
        spent = spent.saturating_add(current.len());
        let next = match String::from_utf8(decode_once(&current)) {
            Ok(next) => next,
            // Bytes that are not valid UTF-8 cannot be shown safely.
            Err(_) => return EchoState::Unstable,
        };
        if next == current {
            // The text stopped changing: there is no deeper copy to read.
            return EchoState::Clean;
        }
        // The scrubber reads the copy too: its bytes are charged as well.
        if spent.saturating_add(next.len()) > budget {
            return EchoState::Unstable;
        }
        spent = spent.saturating_add(next.len());
        if secret_shaped(&next) {
            return EchoState::Secret;
        }
        current = next;
    }
    // The round cap ran out while the text was still changing.
    EchoState::Unstable
}

/// One percent-decoding round: the bytes of `text` with every valid `%XX`
/// escape replaced by its byte. A malformed escape is kept as written.
fn decode_once(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if let Some(byte) = bytes.get(index + 1..index + 3).and_then(hex_pair) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// The byte of two hex digits.
fn hex_pair(pair: &[u8]) -> Option<u8> {
    match pair {
        [high, low] => Some((hex_value(*high)? << 4) | hex_value(*low)?),
        _ => None,
    }
}

/// The value of one hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Mask the identity material the secret scrubber deliberately leaves alone:
/// WhatsApp JIDs and long digit runs.
///
/// Rules:
/// - a JID local part (`<digits>@s.whatsapp.net`, `@lid`, `@g.us`, with an
///   optional `:device` suffix) carrying at least seven digits is replaced by
///   `<jid>`; the server name stays (it carries no identity). This mirrors the
///   vetted rule in `the app's voice::error`; the log path cannot call it directly
///   (`the app's voice crate` sits above `kernel-broker`), so the same boundary logic lives
///   here without the voice-specific extras;
/// - every maximal run of eight or more ASCII digits is replaced by
///   `<number>` (E.164/national phone numbers and any stray long numeric
///   identifier), except the readable shapes: dates, clock times with their
///   fraction and zone, and IPv4 endpoints (`:port`, loopback, or right after
///   a context word such as `host:`). A bare dotted quad such as `41.23.45.67`
///   is masked, since it can be a phone number;
///
/// This is the layer the daemon log writer applies after [`redact_secrets`]
/// (see [`redact_log_line`]): the library crates (`whatsapp-rust`, `wacore*`)
/// log peer identities at `INFO`, and a number or JID must never reach
/// `~/.auxesis/logs/auxd.log`.
pub fn redact_identifiers(text: &str) -> String {
    redact_digit_runs(&redact_grouped_phone_numbers(&redact_jid_identifiers(text)))
}

/// The log-line redactor: the shared secret scrubber ([`redact_secrets`])
/// then the identity scrubber ([`redact_identifiers`]). Every writer the
/// daemon and the app's WhatsApp crate install runs formatted records through this.
pub fn redact_log_line(text: &str) -> String {
    redact_identifiers(&redact_secrets(text))
}

/// Written in place of a log line whose redaction panicked. The text is
/// fixed, so no part of the raw line can reach the log.
pub const REDACTION_ERROR_LINE: &str = "<redaction-error: line dropped>";

/// [`redact_log_line`] for the log writers. A redaction bug must never crash
/// the writer, and a line that cannot be redacted is replaced by
/// [`REDACTION_ERROR_LINE`], never written raw. A caught panic reports only its
/// source location: the process hook is payload-free.
pub fn redact_log_line_guarded(text: &str) -> String {
    guard_log_redaction(text, redact_log_line)
}

/// Run `redact` on `text` behind the log guard. [`redact_log_line_guarded`] is
/// this with [`redact_log_line`]; the redaction step is a parameter so the
/// panic path can be driven from other crates' tests.
pub fn guard_log_redaction(text: &str, redact: impl FnOnce(&str) -> String) -> String {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| redact(text)))
        .unwrap_or_else(|_| REDACTION_ERROR_LINE.to_string())
}

/// JID servers whose `@`-suffixed local part is an identity. Kept in sync
/// with the voice scrubber (`the app's voice::error`).
const IDENTITY_JID_SERVERS: [&str; 3] = ["s.whatsapp.net", "lid", "g.us"];

/// Characters allowed in a JID local part (digits, group dash, device `:`).
fn is_jid_local_char(ch: char) -> bool {
    ch.is_ascii_digit() || matches!(ch, '-' | ':' | '.')
}

/// Can `ch` continue a JID server name? A `.` is handled by
/// [`jid_server_ends`]: it only continues the name when an identifier
/// character follows it.
fn is_jid_tail_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')
}

/// Does the JID server name end where `rest` starts? An identifier character
/// after the name (`1@s.whatsapp.netX`), or a `.` followed by one
/// (`1@lid.example`), makes it a longer name. A sentence full stop after the
/// server (`1@lid.`) ends the JID.
fn jid_server_ends(rest: &str) -> bool {
    let mut chars = rest.chars();
    match chars.next() {
        None => true,
        Some('.') => !chars.next().is_some_and(is_jid_tail_char),
        Some(ch) => !is_jid_tail_char(ch),
    }
}

/// Replace the local part of every WhatsApp JID with `<jid>`.
fn redact_jid_identifiers(text: &str) -> String {
    if !text.contains('@') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('@') {
        let after = &rest[at + 1..];
        let is_jid = IDENTITY_JID_SERVERS
            .iter()
            .any(|server| after.starts_with(*server) && jid_server_ends(&after[server.len()..]));
        if !is_jid {
            out.push_str(&rest[..at + 1]);
            rest = after;
            continue;
        }
        let local_start = rest[..at]
            .char_indices()
            .rev()
            .find(|(_, ch)| !is_jid_local_char(*ch))
            .map(|(index, ch)| index + ch.len_utf8())
            .unwrap_or(0);
        let digits = rest[local_start..at]
            .chars()
            .filter(char::is_ascii_digit)
            .count();
        if digits >= 7 {
            out.push_str(&rest[..local_start]);
            out.push_str("<jid>");
        } else {
            out.push_str(&rest[..at + 1]);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Most separator characters the digit scanner bridges between two digits.
/// Four covers a grouping with a doubled separator (`06..12`).
const MAX_DIGIT_GAP: usize = 4;

/// Replace digit candidates with `<number>`, preserving only whole-candidate
/// dates/times and IPv4 addresses. The scan alphabet folds Unicode decimal
/// digits (the mathematical digit sets included) and decodes `\uXXXX` and
/// `\u{X...}` escapes to the character they name, for any code point. Offsets
/// point into the original text, so a masked span is always the raw span.
/// Ambiguous long numeric content such as durations or lists, UUID/hash digit
/// runs, and IPv6 parts may be masked: in logs, a false positive is cheaper
/// than a leaked identity.
///
/// A candidate is a run of digits joined by at most [`MAX_DIGIT_GAP`]
/// separators, where a separator is neither a digit, alphanumeric nor a line
/// break. A candidate of eight or more digits is kept only when its whole
/// normalised text is a date or a clock time (with an optional fraction and
/// zone), or an IPv4 address that is an endpoint: followed by `:port` (at most
/// 65535), loopback (`127.x.x.x`, `0.0.0.0`), or introduced right before it
/// by a context word such as `host:` or `peer=` (see `ipv4_context`). Every
/// field is range-checked. A bare dotted quad such as `12.34.56.78` is a phone
/// number in several countries, so it is masked. Semantic versions are never
/// kept at eight digits or more: `415.555.1234` has the shape of one. Real versions
/// (`1.2.3`, `rustc 1.90.0`) have fewer than eight digits and are never masked.
fn redact_grouped_phone_numbers(text: &str) -> String {
    #[derive(Clone, Copy)]
    struct Unit {
        ch: char,
        start: usize,
        end: usize,
    }

    fn decimal_digit(c: char) -> Option<char> {
        // Each entry starts a block of ten Nd digits. The table is exact, so it
        // needs no `is_numeric` guard, and it does not depend on the Unicode
        // tables of the toolchain knowing the newest blocks. The last rows add
        // the mathematical sets (U+1D7D8, U+1D7E2, U+1D7EC, U+1D7F6; U+1D7CE is
        // the bold set) and the Unicode 16 blocks.
        const ZEROES: &[u32] = &[
            0x0030, 0x0660, 0x06f0, 0x07c0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0be6, 0x0c66,
            0x0ce6, 0x0d66, 0x0de6, 0x0e50, 0x0ed0, 0x0f20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946,
            0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0,
            0xa9f0, 0xaa50, 0xabf0, 0xff10, 0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0,
            0x112f0, 0x11450, 0x114d0, 0x11650, 0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50,
            0x11d50, 0x11da0, 0x11f50, 0x16a60, 0x16ac0, 0x16b50, 0x1d7ce, 0x1e140, 0x1e2f0,
            0x1e4f0, 0x1e950, 0x1fbf0, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x10d40, 0x11bf0,
            0x16130, 0x16d70, 0x1ccf0, 0x1e5f1,
        ];
        let cp = c as u32;
        ZEROES.iter().find_map(|zero| {
            (cp >= *zero && cp < *zero + 10)
                .then(|| char::from_digit(cp - *zero, 10))
                .flatten()
        })
    }

    /// The character named by a `\uXXXX` or `\u{X...}` escape that starts at
    /// byte `i`, and the byte just past it. Surrogates and values beyond
    /// U+10FFFF name no character, so they stay literal text.
    fn escaped_char(text: &str, i: usize) -> Option<(char, usize)> {
        let bytes = text.as_bytes();
        if bytes.get(i) != Some(&b'\\') || bytes.get(i + 1) != Some(&b'u') {
            return None;
        }
        let (hex, end) = if bytes.get(i + 2) == Some(&b'{') {
            let body = bytes.get(i + 3..)?;
            let close = body.iter().take(7).position(|byte| *byte == b'}')?;
            (&body[..close], i + 3 + close + 1)
        } else {
            (bytes.get(i + 2..i + 6)?, i + 6)
        };
        if hex.is_empty() || hex.len() > 6 || !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let code = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
        char::from_u32(code).map(|ch| (ch, end))
    }

    fn is_format_or_zero_width(c: char) -> bool {
        matches!(
            c as u32,
            0x00ad
                | 0x0600..=0x0605
                | 0x061c
                | 0x06dd
                | 0x070f
                | 0x0890..=0x0891
                | 0x08e2
                | 0x180e
                | 0x200b..=0x200f
                | 0x202a..=0x202e
                | 0x2060..=0x206f
                | 0xfeff
                | 0xfff9..=0xfffb
                | 0x110bd
                | 0x110cd
                | 0x13430..=0x1343f
                | 0x1bca0..=0x1bca3
                | 0x1d173..=0x1d17a
                | 0xe0001
                | 0xe0020..=0xe007f
        )
    }
    fn is_combining(c: char) -> bool {
        matches!(c as u32, 0x0300..=0x036f)
            || unicode_normalization::char::canonical_combining_class(c) != 0
    }

    /// The value of one to nine ASCII digits (nine cannot overflow `u32`).
    fn digits(bytes: &[u8]) -> Option<u32> {
        if bytes.is_empty() || bytes.len() > 9 || !bytes.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(
            bytes
                .iter()
                .fold(0, |n, byte| n * 10 + u32::from(*byte - b'0')),
        )
    }

    /// The value of exactly `width` ASCII digits.
    fn digits_of_width(bytes: &[u8], width: usize) -> Option<u32> {
        if bytes.len() == width {
            digits(bytes)
        } else {
            None
        }
    }

    /// `HH:MM`, optionally `:SS` with a fraction of up to nine digits (after
    /// `.` or `,`), then an optional `Z` or zone. Every field is range-checked.
    fn clock(bytes: &[u8]) -> bool {
        let (time, zone) = match bytes.split_last() {
            Some((&b'Z', time)) => (time, None),
            _ => match bytes.iter().position(|byte| matches!(*byte, b'+' | b'-')) {
                Some(at) => (&bytes[..at], Some(&bytes[at..])),
                None => (bytes, None),
            },
        };
        let time = match zone {
            // A zone may follow one space: `22:28:46 +0000`.
            Some(zone) if zone_ok(zone) => time.strip_suffix(b" ").unwrap_or(time),
            Some(_) => return false,
            None => time,
        };
        let mut fields = time.split(|byte| *byte == b':');
        let hour = fields.next().and_then(|field| digits_of_width(field, 2));
        let minute = fields.next().and_then(|field| digits_of_width(field, 2));
        let (Some(hour), Some(minute)) = (hour, minute) else {
            return false;
        };
        if hour > 23 || minute > 59 {
            return false;
        }
        if let Some(seconds) = fields.next() {
            if fields.next().is_some() {
                return false;
            }
            let mark = seconds.iter().position(|byte| matches!(*byte, b'.' | b','));
            let (second, fraction) = match mark {
                Some(mark) => (&seconds[..mark], Some(&seconds[mark + 1..])),
                None => (seconds, None),
            };
            if digits_of_width(second, 2).is_none_or(|second| second > 59) {
                return false;
            }
            let fraction_ok = fraction.is_none_or(|digits| {
                (1..=9).contains(&digits.len()) && digits.iter().all(u8::is_ascii_digit)
            });
            if !fraction_ok {
                return false;
            }
        }
        true
    }

    /// A zone: `+HH:MM`, `-HH:MM`, `+HHMM` or `-HHMM`.
    fn zone_ok(zone: &[u8]) -> bool {
        let Some((sign, digits)) = zone.split_first() else {
            return false;
        };
        let (hours, minutes) = match digits {
            [h1, h2, b':', m1, m2] => ([*h1, *h2], [*m1, *m2]),
            [h1, h2, m1, m2] => ([*h1, *h2], [*m1, *m2]),
            _ => return false,
        };
        matches!(*sign, b'+' | b'-')
            && digits_of_width(&hours, 2).is_some_and(|hour| hour <= 23)
            && digits_of_width(&minutes, 2).is_some_and(|minute| minute <= 59)
    }

    /// `YYYY-MM-DD` with a year in 1900..=2100, optionally followed by `T` or
    /// a space and a clock time (with its fraction and zone).
    fn date(bytes: &[u8]) -> bool {
        if bytes.len() < 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return false;
        }
        let year = digits_of_width(&bytes[..4], 4);
        let month = digits_of_width(&bytes[5..7], 2);
        let day = digits_of_width(&bytes[8..10], 2);
        let (Some(year), Some(month), Some(day)) = (year, month, day) else {
            return false;
        };
        if !(1900..=2100).contains(&year) {
            return false;
        }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return false,
        };
        if day == 0 || day > days {
            return false;
        }
        match &bytes[10..] {
            [] => true,
            [b'T' | b' ', time @ ..] => clock(time),
            _ => false,
        }
    }

    /// `a.b.c.d`: four octets 0..=255, no leading zero unless the octet is a
    /// lone `0`, and an optional `:port` of at most 65535.
    fn ipv4(candidate: &str) -> bool {
        let (address, port) = match candidate.split_once(':') {
            Some((address, port)) => (address, Some(port)),
            None => (candidate, None),
        };
        let octets: Vec<&str> = address.split('.').collect();
        let octet_ok = |octet: &str| {
            let bytes = octet.as_bytes();
            (1..=3).contains(&bytes.len())
                && (bytes.len() == 1 || bytes[0] != b'0')
                && digits(bytes).is_some_and(|value| value <= 255)
        };
        let port_ok = |port: &str| {
            let bytes = port.as_bytes();
            (1..=5).contains(&bytes.len()) && digits(bytes).is_some_and(|value| value <= 65_535)
        };
        octets.len() == 4 && octets.into_iter().all(octet_ok) && port.is_none_or(port_ok)
    }

    /// The words that introduce an endpoint address (`host: 10.0.0.5`). `from`
    /// and `to` are not among them: `call me from 12.34.56.78` is a phone number.
    fn is_context_word(word: &str) -> bool {
        matches!(
            word,
            "ip" | "addr"
                | "address"
                | "host"
                | "peer"
                | "remote"
                | "client"
                | "server"
                | "bind"
                | "listen"
                | "connect"
                | "src"
                | "dst"
        )
    }

    /// Is one of those words right before the address? Only `=`, `:`, a space or
    /// `"` may sit between them, at most two characters (`host: 10.0.0.5`,
    /// `peer=10.0.0.5`). The word must be whole and ASCII case-insensitive, so
    /// `ship` is not `ip`.
    fn ipv4_context(before: &str) -> bool {
        let word_end = before.trim_end_matches(['=', ':', ' ', '"']);
        let separator = &before[word_end.len()..];
        separator.len() <= 2
            && word_end
                .rsplit(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .is_some_and(|word| is_context_word(&word.to_ascii_lowercase()))
    }

    /// An IPv4-shaped candidate is readable only as an endpoint: followed by a
    /// valid `:port`, loopback (`127.x.x.x`, `0.0.0.0`), or introduced by a
    /// context word (see `ipv4_context`). A bare dotted quad of eight digits is
    /// masked.
    fn ipv4_readable(candidate: &str, before: &str) -> bool {
        if !ipv4(candidate) {
            return false;
        }
        let address = candidate
            .split_once(':')
            .map_or(candidate, |(address, _)| address);
        candidate.contains(':')
            || address.starts_with("127.")
            || address == "0.0.0.0"
            || ipv4_context(before)
    }

    /// The whole-candidate shapes that are readable rather than phones. The
    /// candidate is normalised text, so any non-ASCII character (an en dash, a
    /// euro sign, a combining mark) makes it a number. `before` is the raw text
    /// ahead of the candidate, for the IPv4 context rule.
    fn allowed(candidate: &str, before: &str) -> bool {
        let bytes = candidate.as_bytes();
        candidate.is_ascii() && (clock(bytes) || date(bytes) || ipv4_readable(candidate, before))
    }

    let mut units: Vec<Unit> = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let (ch, end) = escaped_char(text, i).unwrap_or_else(|| {
            let ch = text[i..].chars().next().unwrap_or('\0');
            (ch, i + ch.len_utf8())
        });
        if let Some(digit) = decimal_digit(ch) {
            units.push(Unit {
                ch: digit,
                start: i,
                end,
            });
        } else if !is_format_or_zero_width(ch) {
            units.push(Unit { ch, start: i, end });
        }
        i = end;
    }

    // A combining mark is dropped when the nearest non-mark character on
    // either side is a digit, so an accent cannot split a number.
    let marks: Vec<bool> = units.iter().map(|unit| is_combining(unit.ch)).collect();
    let mut dropped = vec![false; units.len()];
    let mut after_digit = false;
    for (index, unit) in units.iter().enumerate() {
        if marks[index] {
            dropped[index] = after_digit;
        } else {
            after_digit = unit.ch.is_ascii_digit();
        }
    }
    let mut before_digit = false;
    for (index, unit) in units.iter().enumerate().rev() {
        if marks[index] {
            dropped[index] |= before_digit;
        } else {
            before_digit = unit.ch.is_ascii_digit();
        }
    }
    let units: Vec<Unit> = units
        .into_iter()
        .zip(dropped)
        .filter_map(|(unit, gone)| (!gone).then_some(unit))
        .collect();

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut u = 0;
    while u < units.len() {
        if !units[u].ch.is_ascii_digit() {
            u += 1;
            continue;
        }
        let start_u = u;
        let mut end_u = u + 1;
        let mut digit_count = 1;
        while end_u < units.len() {
            if units[end_u].ch.is_ascii_digit() {
                digit_count += 1;
                end_u += 1;
                continue;
            }
            let sep_start = end_u;
            while end_u < units.len()
                && end_u - sep_start < MAX_DIGIT_GAP
                && !units[end_u].ch.is_ascii_digit()
                && !units[end_u].ch.is_alphanumeric()
                && !matches!(units[end_u].ch, '\n' | '\r')
            {
                end_u += 1;
            }
            if end_u == sep_start || end_u == units.len() || !units[end_u].ch.is_ascii_digit() {
                end_u = sep_start;
                break;
            }
            digit_count += 1;
            end_u += 1;
        }
        let first = units[start_u].start;
        let last = units[end_u - 1].end;
        if digit_count >= 8 {
            let normalized: String = units[start_u..end_u].iter().map(|unit| unit.ch).collect();
            if !allowed(&normalized, &text[..first]) {
                out.push_str(&text[cursor..first]);
                out.push_str("<number>");
                cursor = last;
            }
        }
        u = end_u;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Is `bytes[start..end]` the fraction of a clock time (`22:28:46.123456789`,
/// `22:28:46,123`)? The candidate scanner has already vetted the whole time,
/// and a clock fraction is at most nine digits.
fn is_clock_fraction(bytes: &[u8], start: usize, end: usize) -> bool {
    if start < 9 || end - start > 9 || !matches!(bytes[start - 1], b'.' | b',') {
        return false;
    }
    let seconds = &bytes[start - 9..start - 1];
    seconds.iter().enumerate().all(|(index, byte)| {
        if index == 2 || index == 5 {
            *byte == b':'
        } else {
            byte.is_ascii_digit()
        }
    })
}

/// Replace every maximal run of eight or more ASCII digits with `<number>`.
fn redact_digit_runs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            // Not a digit byte: it starts a full UTF-8 character.
            let ch = text[index..].chars().next().unwrap_or('\0');
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index - start >= 8 && !is_clock_fraction(bytes, start, index) {
            out.push_str("<number>");
        } else {
            out.push_str(&text[start..index]);
        }
    }
    out
}

/// L0: fold the separator lookalikes that sit directly after a
/// credential-looking name onto the ASCII separators the tokenizer
/// understands, drop ANSI escape sequences whole (so an SGR reset between a
/// name and its separator cannot break the pair), then strip
/// control/invisible/format characters (keeping `\n`/`\t`, like
/// [`sanitize_text`]).
///
/// The fold is deliberately *not* a whole-text NFKC pass (B5-07/H-05): only
/// `＝`/`﹦` (→ `=`) and `：`/`﹕` (→ `:`), and only when the run immediately
/// before them classifies as a credential name. Every other character —
/// curly quotes, fullwidth letters and digits, CJK punctuation, emoji — is
/// left exactly as it was, so text with nothing to redact stays byte-identical.
fn normalise_for_scrub(text: &str) -> String {
    let stripped = strip_ansi(text);
    let folded = fold_separator_lookalikes(&stripped);
    sanitize_text(&folded)
}

/// Fold `＝`/`﹦`/`：`/`﹕` to `=`/`:` when the name directly before them is
/// credential-shaped; keep the original character otherwise.
fn fold_separator_lookalikes(text: &str) -> String {
    if !text.chars().any(is_separator_lookalike) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for (i, c) in text.char_indices() {
        if let Some(ascii) = separator_lookalike(c) {
            out.push(if credential_name_before(text, i) {
                ascii
            } else {
                c
            });
        } else {
            out.push(c);
        }
    }
    out
}

/// Is the text directly before the separator at byte `at` a credential
/// name — unquoted (`api_key＝…`) or quoted (`{"api_key"：…}`)?
fn credential_name_before(text: &str, at: usize) -> bool {
    const WINDOW: usize = 128;
    let before = &text[..at];
    let trimmed = before.trim_end_matches([' ', '\t']);
    let name = if let Some(quote) = trimmed
        .chars()
        .next_back()
        .filter(|c| *c == '"' || *c == '\'')
    {
        // Quoted key: `"api_key"：`, `" api_key "：`, `'token'：`.
        let quote_len = quote.len_utf8();
        if trimmed.len() < quote_len * 2 {
            return false;
        }
        // The window is a byte count: round its start up to a character
        // boundary. The closing quote is ASCII, so `end` always is one.
        let end = trimmed.len() - quote_len;
        let mut start = trimmed.len().saturating_sub(WINDOW).min(end);
        while !trimmed.is_char_boundary(start) {
            start += 1;
        }
        let content = &trimmed[start..end];
        let Some(open) = content.rfind(quote) else {
            return false;
        };
        content[open + quote_len..].trim()
    } else {
        // Unquoted run immediately before the separator.
        let end = trimmed.len();
        let mut start = end;
        let bytes = trimmed.as_bytes();
        while start > 0 && end - start < WINDOW && is_run_byte(bytes[start - 1]) {
            start -= 1;
        }
        if start == end {
            return false;
        }
        trimmed[start..end].trim()
    };
    !name.is_empty()
        && (header_gate(name).is_some() || classify_name(name).strength != Strength::None)
}

/// The four separator lookalikes the tokenizer aliases: fullwidth equals and
/// colon and their small-form variants.
fn separator_lookalike(c: char) -> Option<char> {
    match c {
        '\u{FF1D}' | '\u{FE66}' => Some('='),
        '\u{FF1A}' | '\u{FE55}' => Some(':'),
        _ => None,
    }
}

fn is_separator_lookalike(c: char) -> bool {
    separator_lookalike(c).is_some()
}

/// Drop ANSI CSI (`ESC [ … final`) and OSC (`ESC ] … BEL`) sequences whole.
///
/// The plain sanitiser strips the ESC byte and leaves the CSI parameters
/// (`api_key[0m=…`); removing the sequence as a unit keeps the pair
/// scannable for every later layer.
fn strip_ansi(text: &str) -> String {
    if !text.contains('\u{1b}') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('[') => {
                chars.next();
                for next in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                for next in chars.by_ref() {
                    if next == '\u{7}' {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// L1a: scrub `text` when it is one JSON document (object, array or string).
///
/// Returns `Some(text)` when the document parsed and was already clean (the
/// original bytes are kept: no formatting is invented), `Some(compact)` when
/// the walk changed it, and `None` when the text is not a JSON document.
///
/// B4-01: "clean" is decided by the *walk*, never by comparing
/// re-serialisations. Re-serialising a clean document would normalise
/// whitespace, escape spelling and (before `arbitrary_precision`) every
/// number through `f64`; a document with nothing to redact is returned
/// byte for byte.
fn scrub_json_document(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"')) {
        return None;
    }
    let mut value: serde_json::Value = serde_json::from_str(text).ok()?;
    // Only containers and strings can carry content; a bare number/bool has
    // nothing to walk.
    if scrub_json_value(&mut value) {
        serde_json::to_string(&value).ok()
    } else {
        Some(text.to_string())
    }
}

/// L1b: scrub every balanced JSON object/array substring of `text`.
///
/// The extractor is a byte state machine (string/escape aware, depth-capped)
/// charged against a global byte budget, so an adversarial text full of
/// `{`/`[` can never turn the structured pass quadratic; once the budget is
/// gone the L2 tokenizer still covers the remaining text.
fn scrub_embedded_json(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut budget = text.len().saturating_mul(2).saturating_add(1024);
    let mut out: Option<String> = None;
    let mut copied = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if (bytes[i] == b'{' || bytes[i] == b'[') && budget > 0 {
            let start = i;
            if let Some(end) = json_region_end(bytes, start, &mut budget) {
                if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&text[start..end])
                {
                    // B4-01: replace the region only when the walk redacted
                    // something; a clean region stays byte-identical.
                    if scrub_json_value(&mut value) {
                        let serialised = serde_json::to_string(&value).unwrap_or_default();
                        let buffer = out.get_or_insert_with(|| String::with_capacity(text.len()));
                        buffer.push_str(&text[copied..start]);
                        buffer.push_str(&serialised);
                        copied = end;
                    }
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.map(|mut buffer| {
        buffer.push_str(&text[copied..]);
        buffer
    })
}

/// Depth cap for the balanced-brace extractor (serde_json's own recursion
/// limit is lower, so a deeper region could never parse anyway).
const JSON_REGION_MAX_DEPTH: usize = 64;

/// End (exclusive) of the balanced `{…}`/`[…]` region starting at `start`,
/// or `None` when it does not close inside the remaining budget. Scans
/// string/escape state so a `}` inside a JSON string cannot end the region.
fn json_region_end(bytes: &[u8], start: usize, budget: &mut usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = start;
    while i < bytes.len() {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let byte = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > JSON_REGION_MAX_DEPTH {
                        return None;
                    }
                }
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Maximum JSON nesting the tree walker descends into before it redacts the
/// whole subtree; a payload deeper than this is treated as opaque.
const JSON_WALK_MAX_DEPTH: usize = 64;

/// Scrub a `serde_json::Value` tree in place: the value of every key whose
/// normalised name names a credential is replaced with the mask, and every
/// string value is passed through [`redact_secrets`] (so a JSON document
/// hidden inside a string is scrubbed before the tree is re-serialised).
///
/// Returns `true` when anything was redacted. Callers that re-serialise a
/// payload — activity digests, WS journal frames — run this *before* turning
/// the value into a string, so a key can never be hidden behind an escape
/// produced by `serde_json` (B3-02). The text entry points keep the original
/// bytes when the result is `false` (B4-01); digest callers may still render
/// the tree, but with `arbitrary_precision`/`preserve_order` enabled (see
/// `Cargo.toml`) its numbers keep their exact original lexemes and its keys
/// keep their input order.
pub fn scrub_json_value(value: &mut serde_json::Value) -> bool {
    scrub_json_inner(value, 0)
}

fn scrub_json_inner(value: &mut serde_json::Value, depth: usize) -> bool {
    use serde_json::Value;
    if depth > JSON_WALK_MAX_DEPTH {
        if !matches!(value, Value::Null) {
            *value = Value::String(MASK.to_string());
            return true;
        }
        return false;
    }
    match value {
        Value::Object(map) => {
            let mut changed = false;
            // E6-02: a secret used as a JSON *key* (`{"<secret>":"owner"}`)
            // must not survive the tree walk either. The raw-text path sees
            // it through the exact layer; the tree path holds values only, so
            // scrub the keys here before anything else reads them.
            let original_keys: Vec<String> = map.keys().cloned().collect();
            for key in &original_keys {
                let scrubbed = redact_secrets(key);
                if scrubbed != *key {
                    if let Some(entry) = map.remove(key.as_str()) {
                        map.insert(scrubbed, entry);
                        changed = true;
                    }
                }
            }
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in &keys {
                let info = classify_name(key);
                let Some(entry) = map.get_mut(key) else {
                    continue;
                };
                if (info.strength != Strength::None || info.aux_key) && mask_json_entry(info, entry)
                {
                    changed = true;
                    continue;
                }
                changed |= scrub_json_inner(entry, depth + 1);
            }
            // E5-01: a credential *name* in one entry and its *value* in a
            // sibling entry (`{"name":"api_key","value":"…"}` — tool-call
            // argument dumps, MCP envelopes, credential managers) defeats
            // the per-key classifier because neither entry is secret-shaped
            // on its own. When an entry names a credential, the sibling
            // value carriers are masked whole.
            let names_credential = keys
                .iter()
                .any(|key| is_name_carrier(key) && map.get(key).is_some_and(credential_name));
            if names_credential {
                for key in &keys {
                    if !is_value_carrier(key) {
                        continue;
                    }
                    if let Some(entry) = map.get_mut(key) {
                        if mask_sibling_value(entry) {
                            changed = true;
                        }
                    }
                }
            }
            changed
        }
        Value::Array(items) => {
            let mut changed = false;
            // E5-01: a two-element tuple whose first item names a credential
            // (`["api_key","…"]`, `["Authorization","Bearer …"]`).
            if items.len() == 2 && credential_name(&items[0]) && mask_sibling_value(&mut items[1]) {
                changed = true;
            }
            for item in items {
                changed |= scrub_json_inner(item, depth + 1);
            }
            changed
        }
        Value::String(text) => {
            let scrubbed = redact_secrets(text);
            if scrubbed != *text {
                *text = scrubbed;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Replace one JSON entry whose key names a credential, when the entry's
/// shape (or, for containers, its content) justifies it. Returns `true` when
/// the entry was replaced.
fn mask_json_entry(info: NameInfo, entry: &mut serde_json::Value) -> bool {
    use serde_json::Value;
    match entry {
        Value::String(text) => {
            if value_is_secret(info, text, true) {
                *entry = Value::String(MASK.to_string());
                return true;
            }
        }
        Value::Number(number) => {
            let text = number.to_string();
            if numeric_secret(info, &text) || value_is_secret(info, &text, false) {
                *entry = Value::String(MASK.to_string());
                return true;
            }
        }
        Value::Array(items) => {
            if !items.is_empty() {
                *entry = Value::String(MASK.to_string());
                return true;
            }
        }
        Value::Object(map) => {
            if !map.is_empty() {
                *entry = Value::String(MASK.to_string());
                return true;
            }
        }
        Value::Bool(_) | Value::Null => {}
    }
    false
}

/// Keys that *carry* a credential name in an envelope object
/// (`{"name":"api_key","value":"…"}`): the value of one of these names the
/// credential whose value sits under a value carrier. E6-01: tool-call
/// dumps use `env`, `var`, `setting`, `option` and `param` for the same
/// carrier role.
fn is_name_carrier(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "name"
            | "key"
            | "header"
            | "field"
            | "variable"
            | "env"
            | "var"
            | "setting"
            | "option"
            | "param"
    )
}

/// Keys that *carry* the credential value next to a name carrier.
fn is_value_carrier(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "value" | "val" | "content" | "data"
    )
}

/// Does this scalar name a credential (`"api_key"`, `"Authorization"`)?
fn credential_name(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => {
            let text = text.trim();
            header_gate(text).is_some() || classify_name(text).strength == Strength::Strong
        }
        _ => false,
    }
}

/// Mask the value that sits next to a credential name; returns `true` when
/// the entry changed. Empty strings/containers and booleans/null carry
/// nothing and stay as they are.
fn mask_sibling_value(entry: &mut serde_json::Value) -> bool {
    use serde_json::Value;
    let replace = match entry {
        Value::String(text) => !text.is_empty(),
        Value::Number(_) => true,
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        Value::Bool(_) | Value::Null => false,
    };
    if replace {
        *entry = Value::String(MASK.to_string());
    }
    replace
}

/// Vendor prefixes whose following run is key material. Order only matters
/// for overlapping prefixes within one family; matching is ASCII
/// case-insensitive and the original spelling is re-emitted.
const TOKEN_PREFIXES: &[&str] = &[
    "github_pat_",
    "glpat-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "xapp-",
    "xoxa-",
    "xoxb-",
    "xoxc-",
    "xoxd-",
    "xoxp-",
    "xoxr-",
    "xoxs-",
    "sk_",
    "sk-",
    "xi-",
    "npm_",
    "AIza",
];

/// Name components whose value is treated as a secret (looser value gate).
const STRONG_NAME_COMPONENTS: &[&str] = &[
    "password",
    "passwd",
    // E5-03/round 6: `DB_PASS`, `PASS`, `PW` are the same credential; the
    // exact-component match keeps `bypass`/`compass`/`passenger` readable
    // (the all-caps suffix rule is the only way these can appear glued).
    "pass",
    "pw",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "credential",
    "credentials",
    "apikey",
    "authtoken",
    "authorization",
    // B3-05: cookie-jar names carry session credentials without a
    // `Cookie:` header in front of them.
    "session",
    "sessionid",
    "jsessionid",
    "sid",
    "csrftoken",
    "csrf",
];

/// Name components that mark an assignment as secret-bearing but use the
/// strict shape gate (`key =`, `*_URL`, `*_URI`, `*_WEBHOOK_URL`, `auth`).
const WEAK_NAME_COMPONENTS: &[&str] = &["key", "url", "uri", "webhook", "auth"];

/// Components that name a digest, not a credential: `public_key_sha256` is a
/// hash of public material and must stay readable (B2-08).
const HASH_NAME_COMPONENTS: &[&str] = &[
    "sha1",
    "sha256",
    "sha512",
    "md5",
    "hash",
    "checksum",
    "digest",
    "fingerprint",
];

/// Adjacent name components that together mean a credential (`api_key`,
/// `access_key`, `private_key`, `auth_token`).
const STRONG_NAME_BIGRAMS: &[(&str, &str)] = &[
    ("api", "key"),
    ("access", "key"),
    ("private", "key"),
    ("auth", "token"),
];

/// How strongly an assignment name marks its value as a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Strength {
    /// Not a secret name.
    #[default]
    None,
    /// Secret-bearing, strict value shape (`key`, `*_URL`).
    Weak,
    /// Secret-bearing, loose value shape (`password`, `token`, …).
    Strong,
}

/// What a name means for redaction.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NameInfo {
    pub(crate) strength: Strength,
    /// The name contains `url`/`uri`/`webhook`.
    url_like: bool,
    /// The name contains `webhook`.
    webhook: bool,
    /// The daemon's own `AUX_KEY_…` env shape: every non-empty value redacts.
    aux_key: bool,
}

/// Classify one assignment name. No allocation: names can be long and there
/// can be many of them on an adversarial input.
///
/// B5-02: leading/trailing padding is ignored — `{" api_key " : …}` names the
/// same credential as `{"api_key": …}`.
pub(crate) fn classify_name(name: &str) -> NameInfo {
    let name = name.trim();
    let mut info = NameInfo::default();
    let mut hash_hint = false;
    let mut previous: Option<&str> = None;
    let mut last: Option<&str> = None;
    for part in name.split(['_', '-', '.']).filter(|part| !part.is_empty()) {
        last = Some(part);
        if STRONG_NAME_COMPONENTS
            .iter()
            .any(|term| part.eq_ignore_ascii_case(term))
        {
            info.strength = Strength::Strong;
        } else if WEAK_NAME_COMPONENTS
            .iter()
            .any(|term| part.eq_ignore_ascii_case(term))
            && info.strength == Strength::None
        {
            info.strength = Strength::Weak;
        }
        if part.eq_ignore_ascii_case("url") || part.eq_ignore_ascii_case("uri") {
            info.url_like = true;
        }
        if part.eq_ignore_ascii_case("webhook") {
            info.url_like = true;
            info.webhook = true;
        }
        if HASH_NAME_COMPONENTS
            .iter()
            .any(|term| part.eq_ignore_ascii_case(term))
        {
            hash_hint = true;
        }
        if let Some(previous) = previous {
            if STRONG_NAME_BIGRAMS.iter().any(|(left, right)| {
                previous.eq_ignore_ascii_case(left) && part.eq_ignore_ascii_case(right)
            }) {
                info.strength = Strength::Strong;
            }
        }
        // CamelCase words inside one part (`secretAccessKey`, `dbPassword`)
        // expose the same terms as the app's case-transition split.
        if part.bytes().any(|byte| byte.is_ascii_uppercase()) {
            let bytes = part.as_bytes();
            let mut word_start = 0usize;
            let mut previous_word: Option<&str> = None;
            for index in 1..=bytes.len() {
                let boundary = index == bytes.len()
                    || (bytes[index].is_ascii_uppercase()
                        && (bytes[index - 1].is_ascii_lowercase()
                            || bytes[index - 1].is_ascii_digit()));
                if !boundary {
                    continue;
                }
                let word = &part[word_start..index];
                if STRONG_NAME_COMPONENTS
                    .iter()
                    .any(|term| word.eq_ignore_ascii_case(term))
                {
                    info.strength = Strength::Strong;
                }
                if let Some(previous_word) = previous_word {
                    if STRONG_NAME_BIGRAMS.iter().any(|(left, right)| {
                        previous_word.eq_ignore_ascii_case(left) && word.eq_ignore_ascii_case(right)
                    }) {
                        info.strength = Strength::Strong;
                    }
                }
                previous_word = Some(word);
                word_start = index;
            }
        }
        // All-caps/digit glued compounds expose a strong term as a suffix
        // (`PGPASSWORD`, `MYSQLPWD`, `SECRETACCESSKEY`); a mixed-case or
        // lowercase part is never suffix-matched, so `monkey`/`keyboard`
        // stay readable.
        if part.len() > 4 && part.bytes().all(|byte| !byte.is_ascii_lowercase()) {
            for term in STRONG_NAME_COMPONENTS {
                if part.len() <= term.len() {
                    continue;
                }
                let tail = part.len() - term.len();
                if part.is_char_boundary(tail) && part[tail..].eq_ignore_ascii_case(term) {
                    info.strength = Strength::Strong;
                }
            }
        }
        previous = Some(part);
    }
    if name.len() >= 8 && name.as_bytes()[..8].eq_ignore_ascii_case(b"aux_key_") {
        info.aux_key = true;
        info.strength = Strength::Strong;
    }
    // B3-07: a name that ends in `id`/`uuid` names an identifier, not the
    // credential itself (`token_id`, `session_id`, `access_key_id`). The
    // `AUX_KEY_` env shape keeps its own rule.
    if !info.aux_key
        && last.is_some_and(|part| {
            part.eq_ignore_ascii_case("id") || part.eq_ignore_ascii_case("uuid")
        })
    {
        return NameInfo::default();
    }
    if info.strength != Strength::Strong && hash_hint {
        // A digest of public material is not key material.
        info.strength = Strength::None;
    }
    info
}

/// How one HTTP header value is gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderGate {
    /// Redact when the value looks like an opaque secret (`Authorization:
    /// none` must survive, P3-10).
    Shaped,
    /// Redact the whole value: the header is a credential by definition.
    Whole,
}

/// Credential headers as a name → gate map; names are matched whole and
/// case-insensitively.
pub(crate) fn header_gate(name: &str) -> Option<HeaderGate> {
    const SHAPED: &[&str] = &["authorization", "proxy-authorization"];
    const WHOLE: &[&str] = &[
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-amz-security-token",
        "x-goog-api-key",
        "x-access-token",
    ];
    if SHAPED
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header))
    {
        return Some(HeaderGate::Shaped);
    }
    if WHOLE.iter().any(|header| name.eq_ignore_ascii_case(header)) {
        return Some(HeaderGate::Whole);
    }
    const HUB: &[u8] = b"x-hub-signature";
    if name.len() > HUB.len() && name.as_bytes()[..HUB.len()].eq_ignore_ascii_case(HUB) {
        return Some(HeaderGate::Whole);
    }
    None
}

/// Bytes that make up a token/name run: identifiers, base64url, JWT dots and
/// scheme `+` (so `mongodb+srv://` is one run). Kept apart from punctuation
/// so a prefix only matches at a run start (`task-sk-1234` is safe).
pub(crate) fn is_run_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+')
}

/// Bytes an opaque token value may contain.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'+' | b'/' | b'=' | b':' | b'@' | b'~'
        )
}

/// Bytes that end an unquoted value.
fn is_value_delim(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            ',' | ';' | '"' | '\'' | ']' | '}' | ')' | '(' | '&' | '|' | '`' | '<' | '>'
        )
}

/// Conservative "this is an opaque token, not an English word or code"
/// test. Catches the B2-09 band: every 16–31 byte opaque run with a digit or
/// punctuation, every run of ≥6 distinct bytes, and everything ≥32 bytes.
fn looks_like_secret(value: &str) -> bool {
    if value.starts_with("eyJ") && value.len() >= 12 {
        return true;
    }
    let len = value.len();
    if len < 16 {
        return false;
    }
    if len >= 32 {
        return true;
    }
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    let mut non_alpha = false;
    for byte in value.bytes() {
        if !byte.is_ascii_alphanumeric() {
            non_alpha = true;
        }
        if !seen[byte as usize] {
            seen[byte as usize] = true;
            distinct += 1;
        }
    }
    non_alpha || distinct >= 6
}

/// Loose value gate for the strongest names: any token-shaped value of at
/// least six bytes that carries a digit, is all-caps/digit, has punctuation,
/// or is long enough to be random. Keeps `short`, `None`, `required` and
/// `parse(input)` readable (B2-08).
///
/// B3-07 tightened the digit disjunct: an all-digit value of ten bytes or
/// more is a numeric id or an epoch (`token: 1699999999999`), and a
/// CamelCase identifier (`password: MySecretValue123`, a type name) is not
/// key material by shape alone.
fn plausible_token(value: &str) -> bool {
    if value.len() < 6 || !value.bytes().all(is_token_byte) {
        return false;
    }
    if value.len() >= 10 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if is_camel_identifier(value) {
        return false;
    }
    if looks_like_secret(value) {
        return true;
    }
    let mut digit = false;
    let mut upper = false;
    let mut lower = false;
    let mut non_alnum = false;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            digit = true;
        } else if byte.is_ascii_uppercase() {
            upper = true;
        } else if byte.is_ascii_lowercase() {
            lower = true;
        } else {
            non_alnum = true;
        }
    }
    digit || (upper && !lower && value.len() >= 8) || (!lower && non_alnum) || value.len() >= 16
}

/// Is this value shaped like a CamelCase identifier — a type name, an enum
/// variant, a function name — rather than an opaque credential?
///
/// Requires at least three words (`MySecretValue123`), every word starting
/// uppercase with a lowercase tail; all-caps (`CANARYE2ECAMEL18`) and
/// lowercase (`hunter2swordfish`) values are never identifiers, so the
/// shipped canaries stay redacted.
fn is_camel_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_uppercase() {
        return false;
    }
    let mut humps = 0usize;
    let mut word_has_lower = false;
    for (index, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_uppercase() {
            if index > 0 && bytes[index - 1].is_ascii_lowercase() {
                humps += 1;
            }
            word_has_lower = false;
        } else if byte.is_ascii_lowercase() {
            word_has_lower = true;
        } else if byte.is_ascii_digit() {
            // digits attach to the current word
        } else {
            return false;
        }
    }
    humps >= 2 && word_has_lower
}

/// Does a `scheme://…` or `scheme%3A%2F%2F…` value carry userinfo
/// credentials? Only the authority (up to `/`, `?`, `#`, whitespace or a
/// quote) is considered.
fn url_has_userinfo(value: &str) -> bool {
    let Some(authority_start) = url_authority_start(value) else {
        return false;
    };
    let authority = &value[authority_start..];
    let end = authority
        .find(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>'))
        .unwrap_or(authority.len());
    authority[..end].contains('@')
}

/// Start of the authority of a URL value: after `://`, or after a
/// percent-encoded `%3A%2F%2F` scheme separator (B3-06). Case-insensitive.
fn url_authority_start(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"://") {
            return Some(i + 3);
        }
        if is_percent_scheme_separator(bytes, i) {
            return Some(i + 9);
        }
        i += 1;
    }
    None
}

/// True when `bytes[p..]` starts with `%3A%2F%2F`, ASCII case-insensitive.
fn is_percent_scheme_separator(bytes: &[u8], p: usize) -> bool {
    const ENCODED: &[u8] = b"%3A%2F%2F";
    bytes.len() >= p + ENCODED.len() && bytes[p..p + ENCODED.len()].eq_ignore_ascii_case(ENCODED)
}

/// Does `value` carry a percent-encoded URL scheme (`scheme%3A%2F%2F…`)?
fn has_percent_scheme(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut p = 0usize;
    while p + 9 <= bytes.len() {
        if !is_percent_scheme_separator(bytes, p) {
            p += 1;
            continue;
        }
        // The run before the separator must itself be a scheme; walking back
        // over scheme bytes is linear overall because `%` ends every run.
        let mut start = p;
        while start > 0 && is_scheme_byte(bytes[start - 1]) {
            start -= 1;
        }
        if start < p && is_scheme(&value[start..p]) {
            return true;
        }
        p += 9;
    }
    false
}

/// One byte of a URL scheme (`http`, `mongodb+srv`, …).
fn is_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

/// Decide whether the value of a secret-named assignment is a secret.
fn value_is_secret(info: NameInfo, value: &str, quoted: bool) -> bool {
    if value.is_empty() {
        return false;
    }
    if info.url_like {
        if url_has_userinfo(value) {
            return true;
        }
        let looks_like_url = value.contains("://") || has_percent_scheme(value);
        if info.webhook && looks_like_url {
            return true;
        }
        if looks_like_url {
            // A credential-free URL stays readable.
            return false;
        }
    }
    if info.aux_key {
        return true;
    }
    if quoted {
        if value.len() < 6 {
            return false;
        }
        if value.chars().any(char::is_whitespace) || value.bytes().any(|byte| !is_token_byte(byte))
        {
            // A quoted passphrase or a value carrying punctuation.
            return true;
        }
    }
    match info.strength {
        Strength::Strong => plausible_token(value),
        Strength::Weak => looks_like_secret(value),
        Strength::None => false,
    }
}

/// B5-03: a numeric JSON value under a strong secret name is key material
/// once it is long enough to be one (the reported shape was an 18-digit
/// `api_key`). Short numbers — ports, counters, epochs — stay readable, and
/// the text tokenizer keeps its own B3-07 rule for `token: 1699999999999`.
fn numeric_secret(info: NameInfo, text: &str) -> bool {
    info.strength == Strength::Strong && text.bytes().filter(u8::is_ascii_digit).count() >= 16
}

/// True when `run` is a URL scheme (`http`, `mongodb+srv`, …).
fn is_scheme(run: &str) -> bool {
    let bytes = run.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// Case-insensitive vendor-prefix match at a run start; returns its length.
pub(crate) fn vendor_prefix(run: &str) -> Option<usize> {
    TOKEN_PREFIXES.iter().find_map(|prefix| {
        (run.len() >= prefix.len()
            && run.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes()))
        .then_some(prefix.len())
    })
}

/// The one-pass redactor: a cursor walks the text, each construct consumes
/// the bytes it decides on, and no text is ever rescanned for a failed
/// candidate (B2-04).
struct Redactor<'a> {
    text: &'a str,
    bytes: &'a [u8],
    out: String,
    /// `text[..copied]` is already in `out`.
    copied: usize,
    cursor: usize,
}

impl Redactor<'_> {
    fn run(mut self) -> String {
        while self.cursor < self.bytes.len() {
            let byte = self.bytes[self.cursor];
            if byte == b'-' && self.try_pem() {
                continue;
            }
            if byte == b'-' && self.try_dash_flag() {
                continue;
            }
            if (byte == b'"' || byte == b'\'') && self.try_quoted_name() {
                continue;
            }
            // A run always starts here: `try_run` consumes the whole run and
            // every masking path lands after a value delimiter, so the old
            // run-start boundary guard was dead code (B3-10).
            if is_run_byte(byte) {
                self.try_run();
                continue;
            }
            self.copy_char();
        }
        self.out.push_str(&self.text[self.copied..]);
        self.out
    }

    fn copy_char(&mut self) {
        let len = self.text[self.cursor..]
            .chars()
            .next()
            .map_or(1, char::len_utf8);
        self.cursor += len;
    }

    fn flush_to(&mut self, end: usize) {
        if end > self.copied {
            self.out.push_str(&self.text[self.copied..end]);
        }
        self.copied = self.copied.max(end);
    }

    /// Replace the bytes `[body_start, consumed_end)` with the mask, keeping
    /// an optional closing quote after the mask. `consumed_end` is the end of
    /// the value (quote included) and becomes the new cursor.
    fn mask_value(
        &mut self,
        body_start: usize,
        body_end: usize,
        consumed_end: usize,
        closed: bool,
    ) {
        self.flush_to(body_start);
        self.out.push_str(MASK);
        if closed {
            self.out.push_str(&self.text[body_end..body_end + 1]);
        }
        self.copied = consumed_end;
        self.cursor = consumed_end;
    }

    /// `-----BEGIN <label>-----` blocks whose label names a private key,
    /// through the matching `-----END <label>-----` (case-insensitive label).
    fn try_pem(&mut self) -> bool {
        const BEGIN: &[u8] = b"-----BEGIN ";
        if !self.bytes[self.cursor..].starts_with(BEGIN) {
            return false;
        }
        let label_start = self.cursor + BEGIN.len();
        let limit = (label_start + 128).min(self.bytes.len());
        let Some(offset) = find_bytes(&self.bytes[label_start..limit], b"-----") else {
            return false;
        };
        let label_end = label_start + offset;
        let marker_end = label_end + b"-----".len();
        let label = &self.text[label_start..label_end];
        if !label.to_ascii_lowercase().contains("private key") {
            return false;
        }
        self.flush_to(self.cursor);
        self.out.push_str(&self.text[self.cursor..marker_end]);
        self.out.push_str(MASK);
        let end_marker = format!("-----END {label}-----");
        match self.text[marker_end..].find(&end_marker) {
            Some(offset) => {
                self.out.push_str(&end_marker);
                let end = marker_end + offset + end_marker.len();
                self.copied = end;
                self.cursor = end;
            }
            // No end marker: everything that follows may be key material.
            None => {
                self.copied = self.bytes.len();
                self.cursor = self.bytes.len();
            }
        }
        true
    }

    /// `curl -u user:pass`, `--user user:pass`, `--password pass`: redact the
    /// next value when it carries a credential shape.
    fn try_dash_flag(&mut self) -> bool {
        const FLAGS: &[&str] = &["--password", "--user", "-u"];
        let mut matched = None;
        for flag in FLAGS {
            if !self.text[self.cursor..].starts_with(flag) {
                continue;
            }
            let after = self.cursor + flag.len();
            // Never read a short flag out of a longer one (`-utf8`, `x-u`).
            if self.cursor > 0
                && (self.bytes[self.cursor - 1] == b'-' || is_run_byte(self.bytes[self.cursor - 1]))
            {
                continue;
            }
            let boundary_ok = match self.bytes.get(after) {
                Some(byte) if byte.is_ascii_whitespace() => true,
                Some(b'=') => true,
                None => true,
                _ => false,
            };
            if !boundary_ok {
                continue;
            }
            matched = Some(flag.len());
            break;
        }
        let Some(flag_len) = matched else {
            return false;
        };
        let mut p = self.cursor + flag_len;
        if self.bytes.get(p) == Some(&b'=') {
            p += 1;
        }
        while p < self.bytes.len() && matches!(self.bytes[p], b' ' | b'\t') {
            p += 1;
        }
        // E6-05: `curl --user=(admin:pass)` — the bracket wrapper is skipped
        // inside the same bounded window as any pair; `<>` is masked whole,
        // `(…)` keeps its parentheses around the mask.
        if let Some((body_start, body_end)) = self.bracket_body(p) {
            let inner = &self.text[body_start..body_end];
            let value = inner.trim();
            if !(value.contains(':') || looks_like_secret(value)) {
                return false;
            }
            if self.bytes[p] == b'<' {
                self.mask_value(p, body_end + 1, body_end + 1, false);
                return true;
            }
            let value_start = body_start + (inner.len() - inner.trim_start().len());
            let value_end = value_start + value.len();
            self.mask_value(value_start, value_end, value_end, false);
            return true;
        }
        let rest = &self.text[p..];
        let end = rest
            .find(|c: char| c.is_whitespace() || is_value_delim(c))
            .unwrap_or(rest.len());
        let value = &self.text[p..p + end];
        if !(value.contains(':') || looks_like_secret(value)) {
            return false;
        }
        self.flush_to(p);
        self.out.push_str(MASK);
        self.copied = p + end;
        self.cursor = self.copied;
        true
    }

    /// One token/name run, consumed in one decision.
    fn try_run(&mut self) {
        let start = self.cursor;
        let mut end = start;
        while end < self.bytes.len() && is_run_byte(self.bytes[end]) {
            end += 1;
        }
        let run = &self.text[start..end];
        // PuTTY/OpenSSH new-format private keys carry no BEGIN marker; the
        // key body follows the header, so everything after it is treated as
        // key material.
        const PUTTY: &[u8] = b"PuTTY-User-Key-File-";
        if run.len() >= PUTTY.len() && run.as_bytes()[..PUTTY.len()].eq_ignore_ascii_case(PUTTY) {
            self.flush_to(start);
            self.out.push_str(&run[..PUTTY.len()]);
            self.out.push_str(MASK);
            self.copied = self.bytes.len();
            self.cursor = self.bytes.len();
            return;
        }
        if let Some(prefix_len) = vendor_prefix(run) {
            if run.len() > 10 {
                self.flush_to(start);
                self.out.push_str(&run[..prefix_len]);
                self.out.push_str(MASK);
                self.copied = end;
                self.cursor = end;
                return;
            }
        }
        if run.as_bytes().starts_with(b"AKIA") {
            let extra = run.as_bytes()[4..]
                .iter()
                .take_while(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                .count();
            if extra >= 16 {
                self.flush_to(start + 4);
                self.out.push_str(MASK);
                self.copied = start + 4 + extra;
                self.cursor = self.copied;
                return;
            }
        }
        if run.len() >= 20
            && run.as_bytes()[..3].eq_ignore_ascii_case(b"eyJ")
            && run.bytes().filter(|byte| *byte == b'.').count() >= 2
        {
            self.flush_to(start + 3);
            self.out.push_str(MASK);
            self.copied = end;
            self.cursor = end;
            return;
        }
        if is_scheme(run) && self.text[end..].starts_with("://") {
            if !self.try_url_userinfo(start, end + "://".len()) {
                self.cursor = end;
            }
            return;
        }
        // B3-06: a percent-encoded DSN (`postgres%3A%2F%2Fu:pass@host`).
        if is_scheme(run) && is_percent_scheme_separator(self.bytes, end) {
            if !self.try_url_userinfo(start, end + 9) {
                self.cursor = end;
            }
            return;
        }
        if !self.try_name(run, end) {
            self.cursor = end;
        }
    }

    /// Replace the userinfo of `scheme://user[:pass]@` (or its
    /// percent-encoded spelling) with the mask; `auth_start` is the first
    /// authority byte, after the scheme separator.
    fn try_url_userinfo(&mut self, start: usize, auth_start: usize) -> bool {
        let mut at = None;
        let mut k = auth_start;
        while k < self.bytes.len() {
            let byte = self.bytes[k];
            if byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>' | b'`' | b'\\'
                )
            {
                break;
            }
            if byte == b'@' {
                at = Some(k);
            }
            k += 1;
        }
        let Some(at) = at else {
            return false;
        };
        self.flush_to(start);
        self.out.push_str(&self.text[start..auth_start]);
        self.out.push_str(MASK);
        self.out.push('@');
        self.copied = at + 1;
        self.cursor = at + 1;
        true
    }

    /// A quoted key (`"api_key"`, `'token'`): unwrap and share the pair rule.
    /// An escaped closing quote (`\"api_key\":…`, a JSON fragment copied out
    /// of an encoded string) closes the name too (B3-02). B5-02: padding
    /// spaces inside the quotes (`" api_key "`) are skipped before and after
    /// the run, so a padded key is still a key.
    fn try_quoted_name(&mut self) -> bool {
        let quote = self.bytes[self.cursor];
        let mut name_start = self.cursor + 1;
        while matches!(self.bytes.get(name_start), Some(b' ' | b'\t')) {
            name_start += 1;
        }
        let mut name_end = name_start;
        while name_end < self.bytes.len() && is_run_byte(self.bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            return false;
        }
        let after_padding = {
            let mut p = name_end;
            while matches!(self.bytes.get(p), Some(b' ' | b'\t')) {
                p += 1;
            }
            p
        };
        let after_name = if self.bytes.get(after_padding) == Some(&quote) {
            after_padding + 1
        } else if self.bytes.get(name_end) == Some(&b'\\')
            && self.bytes.get(name_end + 1) == Some(&quote)
        {
            name_end + 2
        } else {
            return false;
        };
        let name = &self.text[name_start..name_end];
        let gate = header_gate(name);
        let info = classify_name(name);
        if gate.is_none() && info.strength == Strength::None {
            return false;
        }
        self.try_pair(after_name, info, gate)
    }

    /// `Bearer`/`Basic` keyword handling before the name rules.
    fn try_name(&mut self, name: &str, name_end: usize) -> bool {
        if (name.eq_ignore_ascii_case("bearer") || name.eq_ignore_ascii_case("basic"))
            && self.try_scheme_value(name_end)
        {
            return true;
        }
        let gate = header_gate(name);
        let info = classify_name(name);
        if gate.is_none() && info.strength == Strength::None {
            return false;
        }
        self.try_pair(name_end, info, gate)
    }

    /// The body span of a `(…)`/`<…>` wrapper at `p`, bounded by
    /// [`PAIR_SKIP_LIMIT`]; `None` when there is no wrapper or it does not
    /// close inside the window.
    fn bracket_body(&self, p: usize) -> Option<(usize, usize)> {
        let close = match self.bytes.get(p) {
            Some(b'(') => b')',
            Some(b'<') => b'>',
            _ => return None,
        };
        let body_start = p + 1;
        let limit = (body_start + PAIR_SKIP_LIMIT).min(self.bytes.len());
        let mut end = body_start;
        while end < limit && self.bytes[end] != close {
            end += 1;
        }
        if end >= limit || end == body_start {
            return None;
        }
        Some((body_start, end))
    }

    /// Redact a `Bearer <value>` / `Basic <value>` value that looks like an
    /// opaque secret.
    ///
    /// B5-04: the whitespace between scheme and value is skipped with the
    /// same bounded rule as every other pair, so an obs-folded credential
    /// (`Authorization: Bearer\r\n  eyJ…`, what every header wrapper emits)
    /// is one value and not an invisible tail. E6-06: a bracketed value
    /// (`Bearer (…)`) is handled like every other pair's bracket wrapper.
    fn try_scheme_value(&mut self, name_end: usize) -> bool {
        let p = self.skip_pair_whitespace(name_end, PAIR_SKIP_LIMIT);
        if p == name_end {
            return false;
        }
        if let Some((body_start, body_end)) = self.bracket_body(p) {
            let inner = &self.text[body_start..body_end];
            let value = inner.trim();
            if !looks_like_secret(value) {
                return false;
            }
            if self.bytes[p] == b'<' {
                self.mask_value(p, body_end + 1, body_end + 1, false);
                return true;
            }
            let value_start = body_start + (inner.len() - inner.trim_start().len());
            let value_end = value_start + value.len();
            self.mask_value(value_start, value_end, value_end, false);
            return true;
        }
        let quote = self
            .bytes
            .get(p)
            .copied()
            .filter(|byte| *byte == b'"' || *byte == b'\'');
        let body_start = p + usize::from(quote.is_some());
        let (body_end, closed) = self.scan_value(body_start, quote, true);
        let value = &self.text[body_start..body_end];
        if !looks_like_secret(value) {
            return false;
        }
        self.mask_value(body_start, body_end, body_end + usize::from(closed), closed);
        true
    }

    /// A `name<separator>value` pair (also used by quoted keys).
    ///
    /// The separator and the value may be split across lines (pretty-printed
    /// JSON fragments, YAML, a shell line continuation); the skip window is
    /// bounded so an adversarial text stays linear (B3-01).
    fn try_pair(&mut self, name_end: usize, info: NameInfo, gate: Option<HeaderGate>) -> bool {
        // E6-04: a bracketed query suffix (`?auth[token]=`, `?token[]=`) sits
        // between the name run and the separator.
        let p = self.skip_pair_whitespace(name_end, PAIR_SKIP_LIMIT);
        let p = self.skip_pair_whitespace(self.skip_name_bracket_suffix(p), PAIR_SKIP_LIMIT);
        let Some(separator_len) = self.separator_at(p) else {
            return false;
        };
        let is_colon = self.bytes[p] == b':';
        let mut q = self.skip_pair_whitespace(p + separator_len, PAIR_SKIP_LIMIT);
        // SB6-04: a repeated separator (`api_key = = …`, `key%3D%3D…`) names
        // the same pair; consume at most two extras, inside the same bounded
        // windows.
        for _ in 0..2 {
            let Some(extra) = self.separator_at(q) else {
                break;
            };
            q = self.skip_pair_whitespace(q + extra, PAIR_SKIP_LIMIT);
        }
        if let Some(gate) = gate.filter(|_| is_colon) {
            return self.try_header_value(q, gate);
        }
        // B5-01: a value wrapped by the punctuation the same sentence uses
        // — `password=(mysecretpassphrase)`, `api_key=<…>` — is still the
        // value of the pair; the wrapper is skipped inside the same bounded
        // window, never by rescanning.
        if self.try_bracketed_value(q, info) {
            return true;
        }
        // `\"value\"`: the quote of an encoded JSON fragment.
        if self.bytes.get(q) == Some(&b'\\')
            && matches!(self.bytes.get(q + 1), Some(b'"') | Some(b'\''))
        {
            q += 1;
        }
        let quote = self
            .bytes
            .get(q)
            .copied()
            .filter(|byte| *byte == b'"' || *byte == b'\'');
        let body_start = q + usize::from(quote.is_some());
        let (body_end, closed) = self.scan_value(body_start, quote, false);
        let value = &self.text[body_start..body_end];
        if !value_is_secret(info, value, quote.is_some()) {
            return false;
        }
        self.mask_value(body_start, body_end, body_end + usize::from(closed), closed);
        true
    }

    /// E6-04: skip a bracketed suffix on a name (`auth[token]=`,
    /// `token[]=`), inside a constant window.
    fn skip_name_bracket_suffix(&self, p: usize) -> usize {
        if self.bytes.get(p) != Some(&b'[') {
            return p;
        }
        let limit = (p + 64).min(self.bytes.len());
        let mut q = p + 1;
        while q < limit && self.bytes[q] != b']' {
            q += 1;
        }
        if q < limit {
            q + 1
        } else {
            p
        }
    }

    /// Redact a value wrapped in `(…)` or `<…>`.
    ///
    /// B5-01: `(`/`)`/`<`/`>` are value delimiters, so without this the
    /// value after the separator reads as empty and the pair disappears;
    /// `password=(mysecretpassphrase)` — prose, maths, a shell transcript —
    /// leaked verbatim. The scan for the closing bracket is bounded
    /// ([`PAIR_SKIP_LIMIT`]), so this stays linear. Parentheses are kept
    /// around the mask (`api_key=(<redacted>)`); an angle-bracket wrapper is
    /// replaced whole, because `<<redacted>>` is not the `<redacted>` idiom
    /// the rest of the system uses.
    fn try_bracketed_value(&mut self, q: usize, info: NameInfo) -> bool {
        let Some((body_start, end)) = self.bracket_body(q) else {
            return false;
        };
        let inner = &self.text[body_start..end];
        let value = inner.trim();
        if !value_is_secret(info, value, false) {
            return false;
        }
        if self.bytes[q] == b'<' {
            // Mask the wrapper as well: `api_key=<redacted>`.
            self.mask_value(q, end + 1, end + 1, false);
            return true;
        }
        let value_start = body_start + (inner.len() - inner.trim_start().len());
        let value_end = value_start + value.len();
        self.mask_value(value_start, value_end, value_end, false);
        true
    }

    /// Skip the whitespace — including line breaks, indentation, a single
    /// shell line continuation, percent-encoded spaces (SB6-04:
    /// `api_key%20=%20…`) and JSON5 comments (E6-03/B5-05) — between a
    /// name/separator and the value, up to `limit` bytes.
    fn skip_pair_whitespace(&self, mut p: usize, limit: usize) -> usize {
        let end = (p + limit).min(self.bytes.len());
        while p < end {
            match self.bytes[p] {
                b' ' | b'\t' | b'\r' | b'\n' => p += 1,
                b'\\' if matches!(self.bytes.get(p + 1), Some(b'\r' | b'\n')) => p += 1,
                b'%' if self.bytes.get(p + 1) == Some(&b'2')
                    && matches!(self.bytes.get(p + 2), Some(b'0' | b'9')) =>
                {
                    p += 3;
                }
                b'/' if self.bytes.get(p + 1) == Some(&b'*') => {
                    // `/* … */`: skip the comment whole or stop.
                    let mut q = p + 2;
                    let mut closed = false;
                    while q + 1 < end {
                        if self.bytes[q] == b'*' && self.bytes[q + 1] == b'/' {
                            closed = true;
                            break;
                        }
                        q += 1;
                    }
                    if !closed {
                        break;
                    }
                    p = q + 2;
                }
                b'/' if self.bytes.get(p + 1) == Some(&b'/')
                    && p > 0
                    && matches!(self.bytes[p - 1], b' ' | b'\t')
                    && matches!(self.bytes.get(p + 2), Some(b' ' | b'\t')) =>
                {
                    // `// …`: skip to the end of the line. Requiring a space
                    // after `//` keeps a value that starts with `//` (a
                    // protocol-relative URL) from being eaten.
                    let mut q = p + 2;
                    while q < end && self.bytes[q] != b'\n' {
                        q += 1;
                    }
                    p = q;
                }
                _ => break,
            }
        }
        // A `//` comment can end on the window edge, a byte count: round up to
        // a character boundary so callers can slice at `p`.
        while p < self.bytes.len() && !self.text.is_char_boundary(p) {
            p += 1;
        }
        p
    }

    /// Redact a header line's value (to the end of the line, quotes and all).
    ///
    /// The gate looks at a bounded window so an adversarial same-line run of
    /// headers stays linear; a value that passes the gate is redacted through
    /// the whole line (redacting more than was inspected is safe).
    fn try_header_value(&mut self, q: usize, gate: HeaderGate) -> bool {
        const SCAN_LIMIT: usize = 1024;
        let rest = &self.text[q..];
        let line_end = rest.find(['\r', '\n']).unwrap_or(rest.len());
        // The window is a byte count: round it down to a character boundary.
        let mut scan_end = line_end.min(SCAN_LIMIT);
        while !rest.is_char_boundary(scan_end) {
            scan_end -= 1;
        }
        let segment = &rest[..scan_end];
        let value = segment.trim();
        if value.is_empty() {
            return false;
        }
        let redact = match gate {
            HeaderGate::Shaped => looks_like_secret(value),
            HeaderGate::Whole => true,
        };
        if !redact {
            return false;
        }
        let leading = segment.len() - segment.trim_start().len();
        let trailing = rest[..line_end].len() - rest[..line_end].trim_end().len();
        let value_start = q + leading;
        let value_end = q + line_end - trailing;
        self.flush_to(value_start);
        self.out.push_str(MASK);
        self.out.push_str(&self.text[value_end..q + line_end]);
        let consumed = q + line_end;
        self.copied = consumed;
        self.cursor = consumed;
        true
    }

    /// Value span: the matching closing quote when there is one, else up to
    /// the first delimiter (or whitespace for scheme values). The quoted scan
    /// honours `\` escapes (`"a\"b"` is one value, B3-02) and looks across a
    /// bounded window of line breaks for the closing quote (B3-01); every
    /// window is a constant, so a single-line document cannot make the scan
    /// quadratic. Returns `(body_end, closed)`.
    fn scan_value(&self, body_start: usize, quote: Option<u8>, scheme: bool) -> (usize, bool) {
        let rest = &self.text[body_start..];
        match quote {
            Some(quote) => {
                let limit = rest.len().min(QUOTED_SCAN_LIMIT);
                let bytes = rest.as_bytes();
                let mut close = None;
                let mut escaped = false;
                let mut i = 0usize;
                while i < limit {
                    let byte = bytes[i];
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == quote {
                        close = Some(i);
                        break;
                    }
                    i += 1;
                }
                match close {
                    Some(offset) => (body_start + offset, true),
                    None => {
                        // No closing quote: the body is the rest of the line,
                        // as before (a masking gate that fails there cannot
                        // hide a long secret, because a long all-token body
                        // passes the gate or is a digit/identifier band).
                        let line_end = rest.find(['\r', '\n']).unwrap_or(rest.len());
                        (body_start + line_end, false)
                    }
                }
            }
            None => {
                let end = if scheme {
                    rest.find(|c: char| c.is_whitespace() || is_value_delim(c))
                        .unwrap_or(rest.len())
                } else {
                    rest.find(is_value_delim).unwrap_or(rest.len())
                };
                (body_start + end, false)
            }
        }
    }

    /// `=`, `:`, `:=`, `%3D` or `%3A` at `p`.
    fn separator_at(&self, p: usize) -> Option<usize> {
        match self.bytes.get(p).copied()? {
            b'=' => Some(1),
            b':' if self.bytes.get(p + 1) == Some(&b'=') => Some(2),
            b':' => Some(1),
            b'%' if self.bytes.get(p + 1).map(u8::to_ascii_lowercase) == Some(b'3')
                && matches!(
                    self.bytes.get(p + 2).map(u8::to_ascii_lowercase),
                    Some(b'd') | Some(b'a')
                ) =>
            {
                Some(3)
            }
            _ => None,
        }
    }
}

/// ASCII `find` over bytes.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .find(|&index| &haystack[index..index + needle.len()] == needle)
}

/// Sanitize and cap `input` at `max_bytes`, keeping the head **and** the tail
/// (exit codes and error lines live at the end) and marking the cut.
///
/// The cut is made on UTF-8 char boundaries; `max_bytes` is a soft floor as
/// the marker line adds bytes.
pub fn sanitize_external_text(input: &str, max_bytes: usize) -> String {
    cap_head_and_tail(sanitize_text(&strip_ansi(input)), max_bytes)
}

/// [`sanitize_external_text`] that keeps the four bidi isolate controls
/// (U+2066–U+2069): the scrub preview path uses it so secret-free text keeps
/// them byte-for-byte (dh-1 fidelity note). Every other control/invisible
/// character, ANSI escapes included, is still removed.
fn sanitize_external_text_keep_isolates(input: &str, max_bytes: usize) -> String {
    cap_head_and_tail(
        kernel_core::text::sanitize_text_keep_bidi_isolates(&strip_ansi(input)),
        max_bytes,
    )
}

/// Replace the Auxesis home path with `<home>` when there is one.
fn replace_home(cleaned: String, home: &Path) -> String {
    if home.as_os_str().is_empty() || cleaned.is_empty() {
        cleaned
    } else {
        cleaned.replace(&home.display().to_string(), "<home>")
    }
}

/// Keep the head **and** the tail of `cleaned`, marking the cut at
/// `max_bytes` (a soft floor: the marker line adds bytes).
fn cap_head_and_tail(cleaned: String, max_bytes: usize) -> String {
    if cleaned.len() <= max_bytes {
        return cleaned;
    }
    let total = cleaned.len();
    let head_budget = max_bytes * 3 / 4;
    let tail_budget = max_bytes - head_budget;
    let mut head_end = head_budget;
    while head_end > 0 && !cleaned.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = total - tail_budget;
    while tail_start < total && !cleaned.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    let kept_tail = total - tail_start;
    format!(
        "{}\n[truncated: showing first {head_end} and last {kept_tail} of {total} bytes]\n{}",
        &cleaned[..head_end],
        &cleaned[tail_start..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    mod redaction_canaries {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/redaction_canaries.rs"
        ));
    }

    #[test]
    fn grouped_number_candidates_mask_leaks_and_preserve_allow_patterns() {
        for raw in [
            "phone=12 34 56 78",
            "06 12 34 56 78:12",
            "06 12 34 56 78:00",
            "06 12 34 56 78abc",
            "phone06 12 34 56 78",
            "06 12 34 56 78z",
            "06  12 34 56 78",
            "06,12,34,56,78",
            "06_12_34_56_78",
            "06+12+34+56+78",
            "06\\u0031 23 45 67 89",
            "０６ １２ ３４ ５６ ７８",
            "٠٦ ١٢ ٣٤ ٥٦ ٧٨",
            "06\u{0301}12 34 56 78",
            "06\u{058a}12\u{058a}34\u{058a}56\u{058a}78",
        ] {
            let clean = super::redact_grouped_phone_numbers(raw);
            assert!(!clean.chars().any(|c| c.is_numeric()), "{raw} -> {clean}");
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
        }
        for keep in [
            "2026-10-08 22:28:46",
            "2026-10-08T22:28:46.123Z",
            "22:28",
            "127.0.0.1:2893",
            "host: 192.168.10.10",
            "192.168.1.100:443",
            "1.2.3",
            "12.5ms",
            "port 2893",
        ] {
            assert_eq!(super::redact_grouped_phone_numbers(keep), keep);
        }
    }

    #[test]
    fn log_identifiers_do_not_join_phone_groups_across_line_breaks() {
        for line_break in ['\n', '\r'] {
            let raw = format!("06 12 34{line_break}56 78");
            assert_eq!(super::redact_grouped_phone_numbers(&raw), raw);
        }
    }

    #[test]
    fn grouped_number_scan_is_linear_on_four_megabytes() {
        let input = "06,12,34,56,78 ".repeat(4 * 1024 * 1024 / 15);
        let output = super::redact_grouped_phone_numbers(&input);
        assert_eq!(output.matches("<number>").count(), 1);
    }

    #[test]
    fn log_identifiers_mask_jids_and_long_digit_runs() {
        // The P3 batch-2 log-hygiene canary (assembled at runtime so no phone
        // number literal is committed): a `whatsapp-rust` INFO line carrying a
        // number and a JID comes out redacted.
        let number = ["336", "0000", "0000"].concat();
        let jid = format!("{number}@s.whatsapp.net");
        let line = format!("Identity change for +{number} ({jid})");
        let masked = redact_log_line(&line);
        assert!(!masked.contains(&number), "number leaked: {masked}");
        assert!(masked.contains("<number>"), "no number mask: {masked}");
        assert!(masked.contains("<jid>"), "no JID mask: {masked}");
        assert!(
            masked.contains("s.whatsapp.net"),
            "the JID server (no identity) stays: {masked}"
        );

        // Ordinary prose, short numbers and non-JID servers are untouched.
        for keep in [
            "disk-usage is high",
            "port 1234 and pid 5678",
            "user@example.com",
            "12@s.whatsapp.netX",
            "1@s.whatsapp.net",
        ] {
            assert_eq!(redact_identifiers(keep), keep, "mangled {keep:?}");
        }
        assert_eq!(redact_identifiers("call 1234567"), "call 1234567");
        assert_eq!(
            redact_identifiers("call 12345678"),
            "call <number>",
            "eight digits is the mask threshold"
        );
    }

    #[test]
    fn multibyte_separators_around_dates_never_panic_and_are_masked() {
        for raw in [
            "2026-10-08 \u{2014} 12 messages",
            "2026-10-08 \u{2013} 12 messages",
            "2026-01-\u{2014}12345678",
        ] {
            let clean = redact_log_line(raw);
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
            assert!(!clean.chars().any(char::is_numeric), "{raw} -> {clean}");
        }
        for raw in ["\u{20ac}1", "\u{b7}1"] {
            assert_eq!(redact_log_line(raw), raw);
        }
    }

    #[test]
    fn escaped_separators_are_decoded_for_scanning() {
        for raw in [
            "06\\u{a0}12\\u{a0}34\\u{a0}56\\u{a0}78",
            "06\\u00a012\\u00a034\\u00a056\\u00a078",
            "06 12 34\\u{200b}56 78",
            "06 12 34\\u200b56 78",
            "06 12 34 \\u{2014} 56 78",
            "06 12 34 \\u2014 56 78",
        ] {
            let clean = redact_grouped_phone_numbers(raw);
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
            assert!(!clean.chars().any(char::is_numeric), "{raw} -> {clean}");
        }
    }

    #[test]
    fn a_sentence_full_stop_after_a_jid_server_still_ends_the_jid() {
        for raw in ["1234567@s.whatsapp.net.", "1234567@lid.", "1234567@g.us."] {
            let clean = redact_identifiers(raw);
            assert!(clean.starts_with("<jid>"), "{raw} -> {clean}");
            assert!(!clean.contains("1234567"), "{raw} -> {clean}");
        }
        // A longer host name is not a JID server, so it is left alone.
        assert_eq!(
            redact_jid_identifiers("1234567@lid.example"),
            "1234567@lid.example"
        );
    }

    #[test]
    fn combining_marks_next_to_a_digit_never_split_a_number() {
        for raw in [
            "0\u{301}6 12 34 56 78",
            "06 12 34 56 78\u{301}",
            "\u{301}06 12 34 56 78",
            "06 12 34 56\u{301}\u{301} 78",
        ] {
            let clean = redact_grouped_phone_numbers(raw);
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
            assert!(!clean.chars().any(char::is_numeric), "{raw} -> {clean}");
        }
    }

    #[test]
    fn four_separators_join_a_number_and_five_do_not() {
        assert_eq!(
            redact_grouped_phone_numbers("06....12....34....56"),
            "<number>"
        );
        // Documented limit: a fifth separator ends the candidate.
        let spaced = "06.....12.....34.....56";
        assert_eq!(redact_grouped_phone_numbers(spaced), spaced);
    }

    #[test]
    fn date_and_ipv4_shapes_are_masked_when_a_field_is_out_of_range() {
        for raw in [
            "0612-10-08 12:34",
            "061.234.56.78",
            "10.0.0.256:8080",
            "1.20260101.0",
        ] {
            assert_eq!(redact_grouped_phone_numbers(raw), "<number>", "{raw}");
        }
        for keep in [
            "2026-10-08",
            "2026-10-08 22:28:46",
            "2026-10-08T22:28:46.123Z",
            "host: 192.168.10.10",
            "127.0.0.1:2893",
            "192.168.1.100:443",
        ] {
            assert_eq!(redact_grouped_phone_numbers(keep), keep);
        }
    }

    #[test]
    fn version_or_ip_shaped_phone_numbers_are_masked() {
        for raw in [
            "415.555.1234",
            "call 415.555.1234 now",
            "212.555.0100",
            "415.555.\u{ff11}\u{ff12}\u{ff13}\u{ff14}",
        ] {
            let clean = redact_identifiers(raw);
            assert!(clean.contains("<number>"), "{raw} -> {clean}");
            assert!(!clean.contains("555"), "{raw} -> {clean}");
            assert!(!clean.chars().any(char::is_numeric), "{raw} -> {clean}");
        }
    }

    #[test]
    fn mathematical_digits_count_as_digits() {
        // Bold, double-struck, sans, sans-bold and monospace digit sets.
        for zero in [0x1d7ce_u32, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6] {
            let raw: String = (0..8u32)
                .map(|offset| char::from_u32(zero + offset).expect("mathematical digit"))
                .collect();
            assert_eq!(redact_grouped_phone_numbers(&raw), "<number>", "{raw}");
        }
    }

    #[test]
    fn readable_shapes_survive_the_whole_log_path() {
        for keep in [
            "2026-10-08 22:28:46",
            "2026-10-08T22:28:46.123Z",
            "22:28",
            "127.0.0.1:2893",
            "host: 192.168.10.10",
            "192.168.1.100:443",
            "1.2.3",
            "v1.2.3",
            "rustc 1.90.0",
            "12.5ms",
            "port 2893",
        ] {
            assert_eq!(redact_identifiers(keep), keep, "mangled {keep:?}");
            assert_eq!(redact_log_line(keep), keep, "mangled {keep:?}");
        }
    }

    #[test]
    fn multibyte_text_at_every_scan_window_edge_never_panics() {
        // The header, quoted-key and `//` windows are byte counts: each one
        // must be rounded to a character boundary before it slices.
        for pad in 0..4 {
            let spaces = " ".repeat(pad);
            let cases = [
                format!("{spaces}Authorization: {}", "\u{20ac}".repeat(400)),
                format!("{spaces}{}\"api_key\"\u{ff1a}secret", "\u{e9}".repeat(200)),
                format!("{spaces}api_key = // x{}", "\u{e9}".repeat(200)),
            ];
            for raw in &cases {
                let _ = redact_log_line(raw);
            }
            if pad == 0 {
                assert!(!redact_log_line(&cases[0]).contains('\u{20ac}'));
            }
        }
    }

    #[test]
    fn redaction_never_panics_on_random_mixed_text() {
        // Tiny deterministic generator (Knuth's MMIX constants). A fixed seed
        // keeps the corpus reproducible without a new dependency.
        struct Lcg(u64);
        impl Lcg {
            fn below(&mut self, bound: usize) -> usize {
                let next = self.0.wrapping_mul(6_364_136_223_846_793_005);
                self.0 = next.wrapping_add(1_442_695_040_888_963_407);
                usize::try_from((self.0 >> 33) % bound as u64).unwrap_or(0)
            }
        }
        fn fuzz_piece(index: usize) -> &'static str {
            match index {
                0 => "-",
                1 => ":",
                2 => ".",
                3 => " ",
                4 => "/",
                5 => "+",
                6 => "T",
                7 => "Z",
                8 => "=",
                9 => "\"",
                10 => "(",
                11 => ")",
                12 => "@",
                13 => "\n",
                14 => "2026-10-08",
                15 => "22:28:46",
                16 => "api_key",
                17 => "Authorization: ",
                18 => "\\u00a0",
                19 => "\\u{2014}",
                20 => "\\u0031",
                21 => "\\u{301}",
                22 => "@s.whatsapp.net.",
                _ => "\u{ff1a}",
            }
        }
        fn fuzz_multibyte(index: usize) -> char {
            match index {
                0 => '\u{e9}',
                1 => '\u{2014}',
                2 => '\u{20ac}',
                3 => '\u{b7}',
                4 => '\u{4e2d}',
                5 => '\u{1f600}',
                6 => '\u{301}',
                7 => '\u{200b}',
                8 => '\u{ff11}',
                9 => '\u{1d7ce}',
                _ => '\u{a0}',
            }
        }
        let mut rng = Lcg(0x00c0_ffee_5eed_2026);
        for case in 0..20_000 {
            // Every fiftieth case is long enough to cross the byte windows.
            let pieces = if case % 50 == 0 { 300 } else { rng.below(24) };
            let mut input = String::new();
            for _ in 0..pieces {
                match rng.below(3) {
                    0 => input.push(char::from(b'0' + rng.below(10) as u8)),
                    1 => input.push_str(fuzz_piece(rng.below(24))),
                    _ => input.push(fuzz_multibyte(rng.below(11))),
                }
            }
            let _ = redact_grouped_phone_numbers(&input);
            let _ = redact_log_line(&input);
        }
    }

    #[test]
    fn a_panicking_log_redaction_yields_the_fixed_placeholder() {
        let line = "Authorization: Bearer secret-value-1234 06 12 34 56 78";
        crate::install_payload_free_panic_hook();
        let out = guard_log_redaction(line, |_| panic!("redaction bug"));
        assert_eq!(out, REDACTION_ERROR_LINE);
        assert!(!out.contains("secret-value"), "{out}");
        // The guard leaves the thread usable: the next line redacts normally.
        assert_eq!(
            redact_log_line_guarded("call 06 12 34 56 78"),
            "call <number>"
        );
    }

    #[test]
    fn bare_dotted_quads_are_masked_and_endpoints_stay_readable() {
        assert_eq!(redact_grouped_phone_numbers("41.23.45.67"), "<number>");
        assert_eq!(redact_grouped_phone_numbers("192.168.10.10"), "<number>");
        assert_eq!(
            redact_grouped_phone_numbers("call 12.34.56.78"),
            "call <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("ship 41.23.45.67"),
            "ship <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("the tip 41.23.45.67"),
            "the tip <number>"
        );
        // `from` and `to` introduce a sender or a recipient, not an endpoint.
        assert_eq!(
            redact_grouped_phone_numbers("call me from 12.34.56.78"),
            "call me from <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("from the server at 41.23.45.67"),
            "from the server at <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("to 41.23.45.67"),
            "to <number>"
        );
        // A context word counts only when it sits right before the address,
        // with at most two of `=`, `:`, space or `"` between them.
        assert_eq!(
            redact_grouped_phone_numbers("host:  41.23.45.67"),
            "host:  <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("host = 41.23.45.67"),
            "host = <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("host and 41.23.45.67"),
            "host and <number>"
        );
        assert_eq!(
            redact_grouped_phone_numbers("hosts=41.23.45.67"),
            "hosts=<number>"
        );
        for keep in [
            "host: 192.168.1.10",
            "host: 192.168.10.10",
            "host=\"41.23.45.67\"",
            "192.168.1.100:443",
            "127.0.0.1",
            "127.255.255.255",
            "0.0.0.0",
            "peer=10.0.0.5",
            "peer=192.168.10.10",
            "peer=41.23.45.67",
            "IP: 41.23.45.67",
            "Client=41.23.45.67",
        ] {
            assert_eq!(redact_grouped_phone_numbers(keep), keep, "{keep}");
        }
    }

    #[test]
    fn clock_fractions_offsets_and_commas_stay_readable() {
        for keep in [
            "22:28:46.123456789",
            "2026-10-08T22:28:46.123456789Z",
            "2026-10-08 22:28:46 +0000",
            "2026-10-08 22:28:46,123",
            "22:28+0200",
            "22:28:46-05:00",
        ] {
            assert_eq!(redact_identifiers(keep), keep, "mangled {keep:?}");
            assert_eq!(redact_log_line(keep), keep, "mangled {keep:?}");
        }
        // A fraction past nanoseconds, or an out-of-range zone, is not a clock.
        assert_eq!(redact_identifiers("22:28:46.1234567890"), "<number>");
        assert_eq!(redact_identifiers("22:28+2560"), "<number>");
    }

    #[test]
    fn unicode_sixteen_digit_blocks_count_as_digits() {
        for zero in [0x10d40_u32, 0x11bf0, 0x16130, 0x16d70, 0x1ccf0, 0x1e5f1] {
            let raw: String = (0..8u32)
                .map(|offset| char::from_u32(zero + offset).expect("decimal digit"))
                .collect();
            assert_eq!(redact_grouped_phone_numbers(&raw), "<number>", "{raw}");
        }
    }

    /// The full round-2 canary corpus, assembled at runtime so no
    /// vendor-shaped literal is committed (the repo secret scanner must not
    /// find fixtures; values are synthetic either way).
    fn canaries() -> Vec<(String, String)> {
        let mut cases: Vec<(String, String)> = Vec::new();
        let mut add = |raw: String, secret: &str| cases.push((raw, secret.to_string()));

        // --- round 1: assignments, prefixes, PEM, JWT, env ---
        add("DB_PASSWORD=CANARYSECRET123".into(), "CANARYSECRET123");
        add(
            "MY_SERVICE_PASSWORD=CANARYSECRET123".into(),
            "CANARYSECRET123",
        );
        add(
            "GITHUB_CANCELLATION_TOKEN=x\ntoken=CANARYSECRET123".into(),
            "CANARYSECRET123",
        );
        add(
            "notatoken=1 then token=CANARYSECRET123".into(),
            "CANARYSECRET123",
        );
        add(
            "x-token=old and token=CANARYSECRET123".into(),
            "CANARYSECRET123",
        );
        add(
            "api_key=<redacted> markerapi_key allowed — api_key=CANARYSHOP8 markerapi_key".into(),
            "CANARYSHOP8",
        );
        add(
            format!("AKIA{}", "CANARYSHOP4AAA111BBB"),
            "CANARYSHOP4AAA111BBB",
        );
        add(
            format!("ghp_{}", "CANARYSHOP3aaa111bbb"),
            "CANARYSHOP3aaa111bbb",
        );
        add(format!("sk-{}", "canary-SHOP1aaa111"), "canary-SHOP1aaa111");
        add(format!("xoxb-1111-2222-{}", "CANARYSHOP5"), "CANARYSHOP5");
        add("api_key=CANARYSHOP8".into(), "CANARYSHOP8");
        add("password=CANARYSHOP9".into(), "CANARYSHOP9");
        add(
            format!(
                "eyJhbGciOiJIUzI1NiJ9.{}.sig{}",
                "eyJzdWIiOiJDQU5BUlkifQ", "CANARYSHOP6"
            ),
            "CANARYSHOP6",
        );
        add(
            "export AUX_KEY_DEEPSEEK = AUXCANARYSPACED42".into(),
            "AUXCANARYSPACED42",
        );
        add(
            "export AUX_KEY_DEEPSEEK\t=\tAUXCANARYTABBED43".into(),
            "AUXCANARYTABBED43",
        );
        add("ANTHROPIC_API_KEY=CANARYSHOP11".into(), "CANARYSHOP11");
        add(
            "AWS_SECRET_ACCESS_KEY=CANARYawssecret51".into(),
            "CANARYawssecret51",
        );
        add("GITHUB_TOKEN=CANARYghenv54".into(), "CANARYghenv54");
        add("accessToken=CANARYE2ECAMEL18".into(), "CANARYE2ECAMEL18");
        add("dbPassword=CANARYE2ECAMEL19".into(), "CANARYE2ECAMEL19");
        add(
            "secretAccessKey=CANARYE2ECAMEL20".into(),
            "CANARYE2ECAMEL20",
        );
        add(
            "client_secret=CANARYclientsecret50".into(),
            "CANARYclientsecret50",
        );
        add("secret=CANARYsecretword52".into(), "CANARYsecretword52");
        add("api_key=abcdef123456ghi".into(), "abcdef123456ghi");
        add("apikey=abcdef123456ghi".into(), "abcdef123456ghi");
        add("api-key=abcdef123456ghi".into(), "abcdef123456ghi");
        add("token=abcdef123456ghi".into(), "abcdef123456ghi");
        add("password=hunter2swordfish".into(), "hunter2swordfish");
        add("PASSWORD = \"two words secret\"".into(), "two words secret");
        add("Token=0123456789abcdef".into(), "0123456789abcdef");
        add(
            format!("github_pat_{}", "11ABCDEFG0CANARYSHOP2abcdefghij"),
            "11ABCDEFG0CANARYSHOP2abcdefghij",
        );

        // --- B2-01: colon/`:=`/JSON/YAML/ini spellings ---
        add(
            "{\"api_key\":\"CANARYJSONKEY0001\"}".into(),
            "CANARYJSONKEY0001",
        );
        add(
            "{\"password\":\"CANARYE2EJSON02\"}".into(),
            "CANARYE2EJSON02",
        );
        add("{\"token\":\"CANARYE2EJSON03\"}".into(), "CANARYE2EJSON03");
        add(
            "{\"client_secret\":\"CANARYE2EJSON04\"}".into(),
            "CANARYE2EJSON04",
        );
        add(
            "{\"AUX_KEY_DEEPSEEK\":\"CANARYE2EENV10\"}".into(),
            "CANARYE2EENV10",
        );
        add("api_key: CANARYE2EYAML02".into(), "CANARYE2EYAML02");
        add("  password: CANARYE2EYAML05".into(), "CANARYE2EYAML05");
        add("password:CANARYE2ECOLON03".into(), "CANARYE2ECOLON03");
        add("[creds]\napi_key: CANARYE2EINI04".into(), "CANARYE2EINI04");
        add("TOKEN: CANARYE2EUPPER05".into(), "CANARYE2EUPPER05");
        add("token := CANARYE2EWALRUS06".into(), "CANARYE2EWALRUS06");
        add(format!("api_key%3D{}", "CANARYE2EPCT12"), "CANARYE2EPCT12");
        add(
            format!(
                "{{\"api_key\":\"{}\"}} unknown tool.decision",
                "CANARYE2EJSON01"
            ),
            "CANARYE2EJSON01",
        );

        // --- B2-02: URL/URI userinfo + url/uri/webhook names ---
        add(
            "postgres://app:CANARYE2EURL04@db.internal:5432/prod".into(),
            "CANARYE2EURL04",
        );
        add(
            "mongodb+srv://u:CANARYE2EURL05@cluster0/db".into(),
            "CANARYE2EURL05",
        );
        add(
            "redis://:CANARYE2EURL06@cache:6379/0".into(),
            "CANARYE2EURL06",
        );
        add(
            "amqp://guest:CANARYE2EURL07@mq:5672/%2f".into(),
            "CANARYE2EURL07",
        );
        add(
            "https://svc:CANARYE2EURL08@internal.example/db".into(),
            "CANARYE2EURL08",
        );
        add(
            "proxy=https://user:CANARYE2EURL09@proxy:3128".into(),
            "CANARYE2EURL09",
        );
        add(
            "DATABASE_URL=postgres://u:CANARYE2EURL10@h/d".into(),
            "CANARYE2EURL10",
        );
        add(
            format!(
                "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/{}/B00/xx",
                "CANARYHOOK0004"
            ),
            "CANARYHOOK0004",
        );

        // --- B2-03: credential headers ---
        add(
            "X-Api-Key: CANARYE2EHDR06ABCDEFGHIJ".into(),
            "CANARYE2EHDR06ABCDEFGHIJ",
        );
        add(
            "X-Auth-Token: CANARYE2EHDR07ABCDEFGHIJ".into(),
            "CANARYE2EHDR07ABCDEFGHIJ",
        );
        add(
            "Proxy-Authorization: Basic Q0FOQVNZVlJFTEIzNDU2Nzg5".into(),
            "Q0FOQVNZVlJFTEIzNDU2Nzg5",
        );
        add(
            "Cookie: session=CANARYE2ECOOKIE07abcdefghij".into(),
            "CANARYE2ECOOKIE07abcdefghij",
        );
        add(
            "X-Hub-Signature-256: sha256=CANARYE2EHDR08abcdef".into(),
            "CANARYE2EHDR08abcdef",
        );

        // --- B2-05: passphrase / credential(s) ---
        add("GPG_PASSPHRASE=CANARYE2EPASS08".into(), "CANARYE2EPASS08");
        add("SSH_PASSPHRASE=CANARYE2EPASS09".into(), "CANARYE2EPASS09");
        add("AWS_CREDENTIALS=CANARYE2ECRED10".into(), "CANARYE2ECRED10");
        add("DB_CREDENTIAL=CANARYE2ECRED11".into(), "CANARYE2ECRED11");

        // --- B2-06: PEM labels + PuTTY ---
        add(
            format!(
                "-----BEGIN private key-----\n{}\n-----END private key-----",
                "CANARYPEM0005abcdefgh"
            ),
            "CANARYPEM0005abcdefgh",
        );
        add(
            format!(
                "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: test\n\
                 Public-Lines: 6\nAAAAB3NzaC1yc2E\nPrivate-Lines: 2\n{}\nPrivate-MAC: deadbeef",
                "CANARYPUTTY0004abcdefgh"
            ),
            "CANARYPUTTY0004abcdefgh",
        );

        // --- B2-09/B2-11: shape bands and error-body URL credentials ---
        add("Bearer abcdefghijklmnopqrst".into(), "abcdefghijklmnopqrst");
        add(
            "Authorization: 0123456789abcdef0123456789abcdef".into(),
            "0123456789abcdef0123456789abcdef",
        );
        add("http://CANARYE2EERR13@[".into(), "CANARYE2EERR13");
        add(
            format!("curl -u user:{} https://example.com", "CANARYE2ECURL16"),
            "CANARYE2ECURL16",
        );

        // --- round 5: brackets, padded keys, folded schemes, sibling pairs ---
        add(
            format!("api_key=({})", "CANARY_B5_01_PAREN01"),
            "CANARY_B5_01_PAREN01",
        );
        add(
            format!("password=({})", "CANARY_B5_01_PASSW02"),
            "CANARY_B5_01_PASSW02",
        );
        add(
            format!("api_key=<{}>", "CANARY_B5_01_ANGLE3"),
            "CANARY_B5_01_ANGLE3",
        );
        add(
            format!("{{ \" api_key \" : \"{}\" }}", "CANARY_B5_02_PADDED4"),
            "CANARY_B5_02_PADDED4",
        );
        add(
            format!("{{ \"api_key \" : \"{}\"}}", "CANARY_B5_02_PADDED5"),
            "CANARY_B5_02_PADDED5",
        );
        add(
            format!("Bearer\n {}", "CANARY_B5_04_FOLDED06"),
            "CANARY_B5_04_FOLDED06",
        );
        add(
            format!("Basic\n {}", "YWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
            "YWxhZGRpbjpvcGVuIHNlc2FtZQ",
        );
        add(
            format!(
                "{{\"name\":\"api_key\",\"value\":\"{}\"}}",
                "CANARY_E5_01_NAME07"
            ),
            "CANARY_E5_01_NAME07",
        );
        add(
            format!(
                "{{\"key\":\"api_key\",\"value\":\"{}\"}}",
                "CANARY_E5_01_KEY08"
            ),
            "CANARY_E5_01_KEY08",
        );
        add(
            format!(
                "{{\"field\":\"password\",\"content\":\"{}\"}}",
                "CANARY_E5_01_FIELD9"
            ),
            "CANARY_E5_01_FIELD9",
        );
        add(
            format!(
                "{{\"arguments\":{{\"name\":\"api_key\",\"value\":\"{}\"}}}}",
                "CANARY_E5_01_ARG10"
            ),
            "CANARY_E5_01_ARG10",
        );
        add(
            format!("[\"api_key\",\"{}\"]", "CANARY_E5_01_ARRAY1"),
            "CANARY_E5_01_ARRAY1",
        );
        add(
            format!(
                "{{\"variable\":\"DB_PASSWORD\",\"val\":\"{}\"}}",
                "CANARY_E5_01_VAR12"
            ),
            "CANARY_E5_01_VAR12",
        );
        add(
            format!("[\"Authorization\",\"Bearer {}\"]", "CANARY_E5_01_AUTH13"),
            "CANARY_E5_01_AUTH13",
        );

        cases
    }

    /// False-positive corpus: text that must survive `redact_secrets` byte for
    /// byte, paired with the substring that proves it.
    fn false_positives() -> Vec<(String, String)> {
        let mut cases: Vec<(String, String)> = Vec::new();
        let mut add = |raw: &str, keep: &str| cases.push((raw.to_string(), keep.to_string()));

        add("disk-usage is high", "disk-usage");
        add("The Bearer bonds are up", "Bearer bonds");
        add("Tokenization of the input", "Tokenization");
        add("AKIA is just a prefix", "AKIA is just a prefix");
        add(
            "-----BEGIN CERTIFICATE-----\nMIICcanaryCERT\n-----END CERTIFICATE-----",
            "MIICcanaryCERT",
        );
        add("check_id=1234 and password=short", "password=short");
        add("api_key= query parameter", "api_key= query parameter");
        add("token = ", "token =");
        add("eyJhbGciOiJIUzI1NiJ9", "eyJhbGciOiJIUzI1NiJ9");
        add(
            "authorization is required for this route",
            "authorization is required",
        );
        add("I withdrew 100 USD from the bank", "I withdrew 100 USD");
        add("task-sk-1234", "task-sk-1234");
        add("disk-sk-usage", "disk-sk-usage");
        add("risk-sk-1", "risk-sk-1");
        add("public_key_sha256 = 9f2a1b3c", "9f2a1b3c");
        add("let token = parse(input);", "parse(input)");
        add("key = \"abcdefghijkl\"", "abcdefghijkl");
        add(
            "commit 9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90",
            "9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90",
        );
        add(
            "sha256=3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3",
            "3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3",
        );
        add(
            "https://example.com/docs?page=2",
            "https://example.com/docs?page=2",
        );
        add("homepage_url=https://example.com", "https://example.com");
        add(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
            "iVBORw0KGgo",
        );
        add("{\"token\":\"abc\"}", "{\"token\":\"abc\"}");
        add("version: 1.2.3", "version: 1.2.3");
        add("at 12:30:45 the job ran", "12:30:45");
        add(
            "Please rotate the API key in the console",
            "API key in the console",
        );
        add("your password policy", "your password policy");
        add("token bucket rate limiting", "token bucket rate limiting");
        add(
            "The credentials should never be committed",
            "credentials should never",
        );
        add(
            "fn check_key(token: &str) -> bool { token.len() > 0 }",
            "fn check_key(token: &str)",
        );
        add("password: required", "password: required");
        add("token: None", "token: None");
        add("assignment: 1234", "assignment: 1234");
        add("mailto:user@example.com", "mailto:user@example.com");
        add("https://example.com/a@b", "https://example.com/a@b");
        add(
            "Content-Security-Policy: default-src 'self'",
            "Content-Security-Policy",
        );
        add("Secret Santa gift exchange", "Secret Santa");
        add(
            "base_url = \"https://api.example.com/v1\"",
            "https://api.example.com/v1",
        );

        cases
    }

    #[test]
    fn caps_large_text_on_char_boundary() {
        let raw = "é".repeat(100); // 200 bytes
        let capped = sanitize_external_text(&raw, 101);
        assert!(capped.starts_with(&"é".repeat(30)));
        assert!(capped.contains("of 200 bytes"), "marker: {capped}");
        assert!(capped.chars().filter(|c| *c == 'é').count() >= 50);
    }

    #[test]
    fn truncation_keeps_the_tail_marker() {
        let raw = format!("{}{}", "x".repeat(5000), "STDERR-MARKER-END");
        let capped = sanitize_external_text(&raw, 256);
        assert!(capped.contains("STDERR-MARKER-END"), "tail lost");
        assert!(capped.contains("truncated"), "marker lost");
    }

    #[test]
    fn small_text_is_untouched() {
        assert_eq!(sanitize_external_text("hello", 1024), "hello");
    }

    #[test]
    fn error_detail_is_one_safe_capped_line() {
        let home = Path::new("/Users/secret/.auxesis");
        let raw = format!(
            "boom at {}/store.db\u{1b}[31m AUX_KEY_DEEPSEEK=sk-live-abcdef12345 \n\
             second\u{202e} line\n{}",
            home.display(),
            "x".repeat(10_000)
        );
        let clean = sanitize_error_detail(home, &raw, 512);
        assert!(!clean.contains("/Users/secret/.auxesis"), "{clean}");
        assert!(clean.contains("<home>/store.db"), "{clean}");
        assert!(!clean.contains("sk-live-abcdef12345"), "{clean}");
        assert!(clean.contains("AUX_KEY_DEEPSEEK=<redacted>"), "{clean}");
        assert!(
            !clean.contains('\n') && !clean.contains('\u{1b}') && !clean.contains('\u{202e}'),
            "details must be one control-free line: {clean:?}"
        );
        assert!(clean.chars().count() <= 512);
    }

    #[test]
    fn preview_keeps_lines_but_hides_paths_and_keys() {
        let home = Path::new("/Users/secret/.auxesis");
        let raw = format!(
            "line one\ncd {}/agents/main\nAUX_KEY_FAKE=sk-live-abcdef \nline four",
            home.display()
        );
        let clean = scrub_external_preview(home, &raw, 4096);
        assert!(clean.contains("line one\n"), "lines are preserved");
        assert!(!clean.contains("/Users/secret/.auxesis"), "{clean}");
        assert!(clean.contains("<home>/agents/main"), "{clean}");
        assert!(!clean.contains("sk-live-abcdef"), "{clean}");
        assert!(clean.contains("AUX_KEY_FAKE=<redacted>"), "{clean}");
    }

    #[test]
    fn redaction_covers_the_documented_secret_shapes() {
        // (raw text, secret that must not survive)
        let cases: &[(&str, &str)] = &[
            ("token sk-canary-abcdef123456 end", "sk-canary-abcdef123456"),
            (
                "env AUX_KEY_DEEPSEEK=sk-live-abcdef12345 done",
                "sk-live-abcdef12345",
            ),
            (
                "pushed ghp_0123456789abcdefghijklmnopqrstuvwx to the remote",
                "ghp_0123456789abcdefghijklmnopqrstuvwx",
            ),
            (
                "PAT github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789",
                "github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789",
            ),
            ("key id AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"),
            (
                "slack xoxb-123456789012-abcdefghijklmnopqrstuvwx",
                "xoxb-123456789012-abcdefghijklmnopqrstuvwx",
            ),
            (
                "slack xoxp-123456789012-abcdefghijklmnopqrstuvwx",
                "xoxp-123456789012-abcdefghijklmnopqrstuvwx",
            ),
            (
                "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
                "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            ),
            (
                "auth Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            ),
            (
                "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAcanary\n-----END RSA PRIVATE KEY-----",
                "MIIEowIBAAKCAQEAcanary",
            ),
            ("api_key=abcdef123456ghi", "abcdef123456ghi"),
            ("apikey=abcdef123456ghi", "abcdef123456ghi"),
            ("api-key=abcdef123456ghi", "abcdef123456ghi"),
            ("token=abcdef123456ghi", "abcdef123456ghi"),
            ("password=hunter2swordfish", "hunter2swordfish"),
            ("PASSWORD = \"two words secret\"", "two words secret"),
            ("Token=0123456789abcdef", "0123456789abcdef"),
        ];
        for (raw, secret) in cases {
            let clean = redact_secrets(raw);
            assert!(!clean.contains(secret), "leaked {secret:?} in {clean:?}");
            assert!(clean.contains("<redacted>"), "no marker in {clean:?}");
        }
    }

    #[test]
    fn every_canary_in_the_corpus_is_redacted() {
        for (raw, secret) in canaries() {
            let clean = redact_secrets(&raw);
            assert!(!clean.contains(&secret), "leaked {secret:?} in {clean:?}");
            assert!(
                clean.contains("<redacted>"),
                "no marker for {secret:?} in {clean:?}"
            );
        }
    }

    #[test]
    fn shared_secret_redaction_canaries_are_redacted() {
        redaction_canaries::assert_no_canaries(redact_secrets);
    }

    #[test]
    fn canaries_are_redacted_through_every_shared_entry_point() {
        // The API surfaces (activity, WS frames, messages, instructions),
        // notifications and error bodies all funnel into these three
        // functions; none may bypass the shared scrubber.
        let home = Path::new("/Users/secret/.auxesis");
        for (raw, secret) in canaries() {
            let preview = scrub_external_preview(home, &raw, 64 * 1024);
            assert!(
                !preview.contains(&secret),
                "preview leaked {secret:?}: {preview:?}"
            );
            let detail = sanitize_error_detail(home, &raw, 2048);
            assert!(
                !detail.contains(&secret),
                "detail leaked {secret:?}: {detail:?}"
            );
        }
    }

    #[test]
    fn false_positives_survive_every_shared_entry_point() {
        let home = Path::new("/Users/secret/.auxesis");
        for (raw, keep) in false_positives() {
            let clean = redact_secrets(&raw);
            assert!(clean.contains(&keep), "mangled {keep:?} into {clean:?}");
            let preview = scrub_external_preview(home, &raw, 64 * 1024);
            assert!(
                preview.contains(&keep),
                "preview mangled {keep:?} into {preview:?}"
            );
            let detail = sanitize_error_detail(home, &raw, 2048);
            assert!(
                detail.contains(&keep),
                "detail mangled {keep:?} into {detail:?}"
            );
        }
    }

    #[test]
    fn redaction_keeps_ordinary_text_untouched() {
        let cases: &[&str] = &[
            "disk-usage is high",
            "The Bearer bonds are up",
            "Tokenization of the input",
            "AKIA is just a prefix",
            "-----BEGIN CERTIFICATE-----\nMIICcanary\n-----END CERTIFICATE-----",
            "check_id=1234 and password=short",
            "api_key= query parameter",
            "token = ",
            "eyJhbGciOiJIUzI1NiJ9",
            "authorization is required for this route",
            "I withdrew 100 USD from the bank",
        ];
        for raw in cases {
            assert_eq!(redact_secrets(raw), *raw, "ordinary text was rewritten");
        }
    }

    #[test]
    fn redaction_is_shared_with_error_and_preview_scrubbers() {
        let home = Path::new("/Users/secret/.auxesis");
        let raw = format!(
            "at {}/store.db: ghp_0123456789abcdefghijklmnop and password=hunter2swordfish",
            home.display()
        );
        let detail = sanitize_error_detail(home, &raw, 512);
        assert!(
            !detail.contains("ghp_0123456789abcdefghijklmnop"),
            "{detail}"
        );
        assert!(!detail.contains("hunter2swordfish"), "{detail}");
        assert!(!detail.contains("/Users/secret/.auxesis"), "{detail}");

        let preview = scrub_external_preview(home, &raw, 4096);
        assert!(
            !preview.contains("ghp_0123456789abcdefghijklmnop"),
            "{preview}"
        );
        assert!(!preview.contains("hunter2swordfish"), "{preview}");
        assert!(preview.contains("<redacted>"), "{preview}");
    }

    #[test]
    fn assignments_keep_scanning_past_a_glued_occurrence() {
        // P1-1: the first hit of a name used to decide the whole string, so
        // a vendor-prefixed decoy (`markerapi_key`) turned the redactor off.
        let cases: &[(&str, &str)] = &[
            ("DB_PASSWORD=CANARYSECRET123", "CANARYSECRET123"),
            ("MY_SERVICE_PASSWORD=CANARYSECRET123", "CANARYSECRET123"),
            (
                "GITHUB_CANCELLATION_TOKEN=x\ntoken=CANARYSECRET123",
                "CANARYSECRET123",
            ),
            ("notatoken=1 then token=CANARYSECRET123", "CANARYSECRET123"),
            ("x-token=old and token=CANARYSECRET123", "CANARYSECRET123"),
            ("password=CANARYSECRET123", "CANARYSECRET123"),
            (
                "api_key=<redacted> markerapi_key allowed — api_key=CANARYSHOP8 markerapi_key",
                "CANARYSHOP8",
            ),
        ];
        for (raw, secret) in cases {
            let clean = redact_secrets(raw);
            assert!(!clean.contains(secret), "leaked {secret:?} in {clean:?}");
        }
    }

    #[test]
    fn vendor_prefixed_names_and_spaced_dotenv_assignments_are_redacted() {
        // P2-4: everything an operator puts in an env file; P2-3: the
        // dotenv-legal `NAME = value` form `parse_dotenv` actually loads.
        let cases: &[(&str, &str)] = &[
            ("ANTHROPIC_API_KEY=CANARYSHOP11", "CANARYSHOP11"),
            (
                "AWS_SECRET_ACCESS_KEY=CANARYawssecret51",
                "CANARYawssecret51",
            ),
            ("OPENAI_API_KEY=CANARYSHOP12", "CANARYSHOP12"),
            ("GITHUB_TOKEN=CANARYghenv54", "CANARYghenv54"),
            ("client_secret=CANARYclientsecret50", "CANARYclientsecret50"),
            ("secret=CANARYsecretword52", "CANARYsecretword52"),
            (
                "export AUX_KEY_DEEPSEEK = AUXCANARYSPACED42",
                "AUXCANARYSPACED42",
            ),
            (
                "export AUX_KEY_DEEPSEEK\t=\tAUXCANARYTABBED43",
                "AUXCANARYTABBED43",
            ),
        ];
        for (raw, secret) in cases {
            let clean = redact_secrets(raw);
            assert!(!clean.contains(secret), "leaked {secret:?} in {clean:?}");
            assert!(clean.contains("<redacted>"), "no marker in {clean:?}");
        }
    }

    #[test]
    fn redaction_preserves_the_spelling_it_matched() {
        // P3-10: the redactor used to re-emit its constant name and swallow
        // the whitespace around `=`, mangling the env-dump text it protects.
        assert_eq!(
            redact_secrets("PASSWORD=CANARYSECRET123"),
            "PASSWORD=<redacted>"
        );
        assert_eq!(redact_secrets("Api_Key=abcdef123456"), "Api_Key=<redacted>");
        assert_eq!(redact_secrets("API-KEY=abcdef123456"), "API-KEY=<redacted>");
        assert_eq!(
            redact_secrets("PASSWORD = \"two words secret\""),
            "PASSWORD = \"<redacted>\""
        );
        // B2-08: `token` here is a code identifier, not an assignment value.
        assert_eq!(
            redact_secrets("let token = parse(input);"),
            "let token = parse(input);"
        );
        // A bare `Authorization: none` is not a secret and must survive.
        assert_eq!(redact_secrets("AUTHORIZATION: none"), "AUTHORIZATION: none");
        assert_eq!(
            redact_secrets("Authorization: off\n"),
            "Authorization: off\n"
        );
        // Idempotent: the mask itself is not re-redacted.
        assert_eq!(redact_secrets("api_key=<redacted>"), "api_key=<redacted>");
        assert_eq!(
            redact_secrets("AUX_KEY_X=<redacted>"),
            "AUX_KEY_X=<redacted>"
        );
    }

    #[test]
    fn colon_delimited_assignments_are_redacted_with_structure_kept() {
        // B2-01: JSON, YAML/ini and `:=` spellings of the same names.
        assert_eq!(
            redact_secrets("{\"api_key\":\"CANARYJSONKEY0001\"}"),
            "{\"api_key\":\"<redacted>\"}"
        );
        assert_eq!(
            redact_secrets("api_key: CANARYE2EYAML02"),
            "api_key: <redacted>"
        );
        assert_eq!(
            redact_secrets("token := CANARYE2EWALRUS06"),
            "token := <redacted>"
        );
        assert_eq!(
            redact_secrets("{\"AUX_KEY_DEEPSEEK\":\"CANARYE2EENV10\"}"),
            "{\"AUX_KEY_DEEPSEEK\":\"<redacted>\"}"
        );
        // Percent-encoded separators (B2-10).
        assert_eq!(
            redact_secrets("api_key%3DCANARYE2EPCT12"),
            "api_key%3D<redacted>"
        );
    }

    #[test]
    fn url_userinfo_credentials_are_redacted_and_plain_urls_survive() {
        // B2-02: any scheme, empty user, `+` schemes; host stays readable.
        assert_eq!(
            redact_secrets("postgres://app:CANARYE2EURL04@db.internal:5432/prod"),
            "postgres://<redacted>@db.internal:5432/prod"
        );
        assert_eq!(
            redact_secrets("redis://:CANARYE2EURL06@cache:6379/0"),
            "redis://<redacted>@cache:6379/0"
        );
        assert_eq!(
            redact_secrets("mongodb+srv://u:CANARYE2EURL05@cluster0/db"),
            "mongodb+srv://<redacted>@cluster0/db"
        );
        assert_eq!(
            redact_secrets("DATABASE_URL=postgres://u:CANARYE2EURL10@h/d"),
            "DATABASE_URL=<redacted>"
        );
        assert_eq!(
            redact_secrets("https://example.com/docs?page=2"),
            "https://example.com/docs?page=2"
        );
        assert_eq!(
            redact_secrets("homepage_url=https://example.com"),
            "homepage_url=https://example.com"
        );
        // B2-11: an error-body URL credential.
        assert_eq!(
            redact_secrets("base_url `\"http://CANARYE2EERR13@[\"` is not valid"),
            "base_url `\"http://<redacted>@[\"` is not valid"
        );
    }

    #[test]
    fn credential_headers_are_redacted_whole() {
        // B2-03: the header name, not only `authorization`.
        assert_eq!(
            redact_secrets("X-Api-Key: CANARYE2EHDR06ABCDEFGHIJ"),
            "X-Api-Key: <redacted>"
        );
        assert_eq!(
            redact_secrets("Proxy-Authorization: Basic Q0FOQVNZVlJFTEIzNDU2Nzg5"),
            "Proxy-Authorization: <redacted>"
        );
        assert_eq!(
            redact_secrets("Cookie: session=CANARYE2ECOOKIE07abcdefghij"),
            "Cookie: <redacted>"
        );
        assert_eq!(
            redact_secrets("X-Hub-Signature-256: sha256=CANARYE2EHDR08abcdef"),
            "X-Hub-Signature-256: <redacted>"
        );
        // Shapes gate: `none` survives, a 32-byte value does not (B2-09).
        assert_eq!(redact_secrets("Authorization: none"), "Authorization: none");
        assert_eq!(
            redact_secrets("Authorization: 0123456789abcdef0123456789abcdef"),
            "Authorization: <redacted>"
        );
        // B3-09: `Whole` is not `Shaped`. A short, low-entropy credential
        // header value is still a credential and must redact, even though
        // `looks_like_secret` would keep it. This is the pin for mutation
        // P03 (every `Whole` downgraded to `Shaped`).
        assert_eq!(redact_secrets("Cookie: sid=abc"), "Cookie: <redacted>");
        assert_eq!(redact_secrets("Set-Cookie: id=a"), "Set-Cookie: <redacted>");
        assert_eq!(redact_secrets("X-Api-Key: abc123"), "X-Api-Key: <redacted>");
        assert_eq!(
            redact_secrets("X-Goog-Api-Key: ab12"),
            "X-Goog-Api-Key: <redacted>"
        );
        assert_eq!(
            redact_secrets("X-Amz-Security-Token: short"),
            "X-Amz-Security-Token: <redacted>"
        );
    }

    #[test]
    fn multi_line_and_escaped_pairs_are_redacted() {
        // B3-01: a value on the line after the key/separator is the shape
        // `jq`, `to_string_pretty`, YAML and a shell continuation produce.
        let pretty = "{\n  \"api_key\":\n    \"CANARY_E3E_MULTI01\"\n}";
        assert_eq!(
            redact_secrets(pretty),
            "{\"api_key\":\"<redacted>\"}",
            "pretty JSON is parsed and re-serialised"
        );
        assert_eq!(
            redact_secrets("api_key:\n  CANARY_E3E_MULTI04"),
            "api_key:\n  <redacted>"
        );
        assert_eq!(
            redact_secrets("export API_KEY=\\\nCANARY_E3E_MULTI07"),
            "export API_KEY=\\\n<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key:\r\n  CANARY_E3E_MULTI05"),
            "api_key:\n  <redacted>"
        );
        // A quoted value broken over lines is one value (kills mutation P09,
        // which stops the quoted scan at the first newline).
        assert_eq!(
            redact_secrets("password: \"hidden\nCANARY_E3E_QNL01\""),
            "password: \"<redacted>\""
        );
        // B3-02: escaped quotes cannot hide a key or a value.
        assert_eq!(
            redact_secrets("{\"detail\":\"{\\\"api_key\\\":\\\"CANARYJSONKEY0001\\\"}\"}"),
            "{\"detail\":\"{\\\"api_key\\\":\\\"<redacted>\"}"
        );
        assert_eq!(
            redact_secrets("{\"password\":\"a\\\"b CANARY_E3E_ESCQ02\"}"),
            "{\"password\":\"<redacted>\"}"
        );
    }

    #[test]
    fn lookalike_separators_and_invisibles_fold_before_scanning() {
        // B3-03/B3-04: the log writer used to run the redactor without the
        // sanitiser, and fullwidth forms were never folded. Both now happen
        // inside the one entry point.
        assert_eq!(
            redact_secrets("token\u{200b}=CANARY_E3E_LOG01"),
            "token=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_\u{200b}key=CANARY_E3E_LOG02"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_\u{00ad}key=CANARY_E3E_LOG03"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key\u{00a0}=CANARY_E3E_LOG04"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key\u{1b}[0m=CANARY_E3E_LOG07"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("token=\u{202e}CANARY_E3E_LOG08"),
            "token=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key＝CANARY_E3E_UNI04"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key：CANARY_E3E_UNI05"),
            "api_key:<redacted>"
        );
    }

    #[test]
    fn cookie_jars_and_percent_urls_are_redacted() {
        // B3-05: a bare cookie jar has no `Cookie:` header name.
        assert_eq!(
            redact_secrets("session=CANARY_E3E_COOKIE09abcdefghij; Path=/; HttpOnly"),
            "session=<redacted>; Path=/; HttpOnly"
        );
        assert_eq!(
            redact_secrets("sid=CANARY_E3E_COOKIE11abcdefghijklmno"),
            "sid=<redacted>"
        );
        assert_eq!(
            redact_secrets("JSESSIONID=CANARY_E3E_COOKIE10abcdefghij"),
            "JSESSIONID=<redacted>"
        );
        // A cookie jar inside `Cookie:` keeps the entire line redacted.
        assert_eq!(
            redact_secrets("Cookie: a=1; session=CANARY_E3E_COOKIE13abcdef; Path=/"),
            "Cookie: <redacted>"
        );
        // B3-06: percent-encoded scheme separators.
        assert_eq!(
            redact_secrets("postgres%3A%2F%2Fu:CANARY_E3E_URL13@h/d"),
            "postgres%3A%2F%2F<redacted>@h/d"
        );
        assert_eq!(
            redact_secrets("postgres%3a%2f%2fu:CANARY_E3E_URL15@h/d"),
            "postgres%3a%2f%2f<redacted>@h/d"
        );
        assert_eq!(
            redact_secrets("DATABASE_URL=postgres%3A%2F%2Fu:CANARY_E3E_URL14@h/d"),
            "DATABASE_URL=<redacted>"
        );
    }

    #[test]
    fn identifier_shaped_values_survive() {
        // B3-07: a UUID under an `*_id` name, an epoch under `token`, a
        // CamelCase type name under `password`.
        let uuid = "7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8";
        for raw in [
            format!("token_id: {uuid}"),
            format!("session_id={uuid}"),
            format!("access_key_id: {uuid}"),
            "token: 1699999999999".to_string(),
            "password: MySecretValue123".to_string(),
        ] {
            assert_eq!(redact_secrets(&raw), raw, "mangled {raw}");
        }
        // The same shapes under a credential name still redact.
        let clean = redact_secrets("password: 7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8");
        assert!(clean.contains("<redacted>"), "{clean}");
    }

    #[test]
    fn json_value_trees_are_scrubbed_before_serialisation() {
        // The activity/WS summary path holds a `Value` before it becomes a
        // string (B3-02): the walker must mask credential keys and recurse
        // into JSON hidden inside string values.
        let mut value: serde_json::Value = serde_json::from_str(
            "{\"api_key\":\"CANARYJSONKEY0001\",\"agent\":\"main\",\"nested\":{\"token\":\"CANARY_E3E_NEST06\"},\"detail\":\"{\\\"password\\\":\\\"CANARY_E3E_ESCQ03\\\"}\",\"id\":1699999999999}",
        )
        .unwrap();
        scrub_json_value(&mut value);
        let serialised = serde_json::to_string(&value).unwrap();
        for secret in [
            "CANARYJSONKEY0001",
            "CANARY_E3E_NEST06",
            "CANARY_E3E_ESCQ03",
        ] {
            assert!(
                !serialised.contains(secret),
                "leaked {secret}: {serialised}"
            );
        }
        assert!(serialised.contains("<redacted>"), "{serialised}");
        // A false positive survives the walk.
        let mut fp: serde_json::Value =
            serde_json::from_str("{\"token\":\"abc\",\"token_id\":\"abc\"}").unwrap();
        scrub_json_value(&mut fp);
        assert_eq!(fp.to_string(), "{\"token\":\"abc\",\"token_id\":\"abc\"}");
        // M09 pin (round-5 mutation survived): a container under a strong
        // key is masked whole; nothing asserted this before.
        let mut containers: serde_json::Value =
            serde_json::from_str(r#"{"api_key":["a","b"],"deep":{"password":{"x":1}}}"#).unwrap();
        scrub_json_value(&mut containers);
        assert_eq!(
            containers.to_string(),
            r#"{"api_key":"<redacted>","deep":{"password":"<redacted>"}}"#
        );
        // E5-01 through the tree walk (the activity/WS summary path).
        let mut siblings: serde_json::Value =
            serde_json::from_str(r#"{"detail":{"name":"api_key","value":"CANARY_E5TREE09"}}"#)
                .unwrap();
        scrub_json_value(&mut siblings);
        let serialised = siblings.to_string();
        assert!(!serialised.contains("CANARY_E5TREE09"), "{serialised}");
    }

    // ---- B4-01/B4-02: the structured layer never rewrites non-secret JSON ----

    /// The guarantee under test, stated once: a JSON document (whole or a
    /// balanced substring) with nothing to redact comes back **byte for
    /// byte** — whitespace, escape spelling, duplicate keys, key order and
    /// every number lexeme included. When something *is* redacted, the
    /// changed region is re-serialised compactly with keys in input order
    /// (`preserve_order`) and numbers in their exact original lexemes
    /// (`arbitrary_precision`); non-secret content is then semantically, not
    /// byte, identical, and text outside the changed region is untouched.
    fn clean_json_payloads() -> Vec<String> {
        [
            r#"{"version":"0.1.0","pid":48213,"at":"2026-10-05 09:12:33"}"#,
            r#"{"agent":"main","tool":"shell","outcome":"allowed","reason":"command matched the allowlist"}"#,
            r#"{"agent":"main","tool":"read","outcome":"denied","reason":"path outside the workspace"}"#,
            r#"{"agent":"main","summary":"fetched https://example.com/docs","status":200,"duration_ms":183}"#,
            r#"{"run_id":18446744073709551615,"state":"ok"}"#,
            r#"{"weight":1e22,"ratio":0.1,"scale":1.0,"epsilon":1e-7}"#,
            r#"{"neg":-9223372036854775808,"big":123456789012345678901234567890}"#,
            r#"{"msg":"caf\u00e9 \u2014 fine","tags":["a","b"]}"#,
            r#"{"ordering":{"z":1,"a":2,"m":3}}"#,
            r#"{"dup":1,"dup":2}"#,
            r#"{
  "agent": "main",
  "jobs_total": 3,
  "jobs_enabled": 2,
  "running_job": null
}"#,
            r#"{"stop":false,"paused":false,"killed":false}"#,
            r#"{"usage_today":{"input_tokens":1234,"output_tokens":567,"requests":12}}"#,
            r#"{"input_tokens":18446744073709551615,"output_tokens":0}"#,
            r#"{"model":"deepseek-v4.1-flash","provider":"opencode-go"}"#,
            r#"{"sessions":[{"id":1,"agent":"main","messages":42},{"id":2,"agent":"side","messages":7}]}"#,
            r#"{"path":"/Users/someone/auxesis/crates/aux-tools/src/text.rs","bytes":12345}"#,
            r#"{"sha256":"3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3"}"#,
            r#"{"commit":"9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90"}"#,
            r#"{"link":"https://example.com/docs?page=2","status":200}"#,
            r#"{"body":"line one\nline two","empty":""}"#,
            r#"{"escaped":"say \"hello\" and \\ the world","nested":"{\"detail\":{\"ok\":true}}"}"#,
            r#"{"tabs":"a\tb","slash":"a/b"}"#,
            r#"{"boolean":true,"nothing":null,"zero":0}"#,
            r#"{"arr":[],"obj":{}}"#,
            r#"{"deep":{"a":{"b":{"c":{"d":{"e":1}}}}}}"#,
            r#"{"list":[1,2,3,4,5,6,7,8,9,10]}"#,
            r#"{"mixed":[true,null,"s",3.5,{"k":"v"}]}"#,
            r#"{"ts":"2026-10-05T09:12:33Z","epoch":1759655553}"#,
            r#"{"email":"owner@example.com","name":"Alex"}"#,
            r#"{"message":"the quick brown fox jumps over the lazy dog"}"#,
            r#"{"assistant":"I will read the file and report back.\nNo changes made."}"#,
            r#"{"role":"assistant","content":"done — 3 tests green"}"#,
            r#"{"job":"nightly-backup","schedule":"0 3 * * *","enabled":true}"#,
            r#"{"next_run_at":"2026-10-06 03:00:00","last_run_at":"2026-10-05 03:00:02"}"#,
            r#"{"kind":"workspace.trust_requested","payload":{"agent":"main","fingerprint":"ab12cd34"}}"#,
            r#"{"fingerprint_sha256":"ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"}"#,
            r#"{"cache_hits":999999999999,"cache_misses":0}"#,
            r#"{"latency_p50_ms":12.75,"latency_p99_ms":1301.5}"#,
            r#"{"percent":100,"fraction":0.0001,"negative":-0.5}"#,
            r#"{"version":"v2.3.4-beta.1+build.5"}"#,
            r#"{"name":"agent-name","display":"Agent Name","hue":210}"#,
            r#"{"thread_id":null,"session_id":"7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8"}"#,
            r#"{
    "entries": [
        {"at": "2026-10-05 09:00:00", "kind": "daemon.started"},
        {"at": "2026-10-05 09:00:01", "kind": "message.user"}
    ],
    "limit": 50
}"#,
            r#"{"escaped_unicode":"\u0041\u0042\u0043","actual":"ABC"}"#,
            r#"{"solidus":"a\/b","tilde":"~"}"#,
            r#"{"array_of_arrays":[[1,2],[3,4],[[5]]]}"#,
            r#"{"unicode_text":"日本語のテキストと emoji 🚀","ascii":"ok"}"#,
            r#"{"summary":"nothing to see here","ok":true}"#,
            r#"{"nested_string":"{\"count\":10000000000000000000000}"}"#,
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn fifty_realistic_clean_payloads_survive_byte_for_byte() {
        let payloads = clean_json_payloads();
        assert_eq!(payloads.len(), 50, "the B4-01 corpus is the contract");
        let home = Path::new("/definitely-not-the-home");
        for (index, payload) in payloads.iter().enumerate() {
            assert_eq!(
                redact_secrets(payload),
                *payload,
                "redact_secrets altered payload {index}:\n{payload}"
            );
            assert_eq!(
                scrub_external_preview(home, payload, 1 << 20),
                *payload,
                "scrub_external_preview altered payload {index}:\n{payload}"
            );
        }
    }

    #[test]
    fn json_numbers_keep_their_exact_lexeme() {
        // B4-02: `arbitrary_precision` keeps the source spelling of every
        // number — no `f64` round trip, no exponent re-formatting.
        for lexeme in [
            "18446744073709551615", // u64::MAX
            "-9223372036854775808", // i64::MIN
            "123456789012345678901234567890",
            "1e22",
            "1E+22",
            "1e-7",
            "0.1",
            "1.0",
            "0.30000000000000004",
            "3.141592653589793238462643383279",
        ] {
            let raw = format!("{{\"n\":{lexeme},\"label\":\"keep\"}}");
            assert_eq!(redact_secrets(&raw), raw, "number {lexeme} rewritten");
        }
        // The same holds when a sibling *is* redacted: only the secret's
        // value changes; number lexemes and key order survive.
        let raw =
            r#"{"z":18446744073709551615,"api_key":"CANARYNUM01abcdef","a":1e+22,"f":1.0,"k":0.1}"#;
        let clean = redact_secrets(raw);
        assert!(!clean.contains("CANARYNUM01abcdef"), "{clean}");
        for lexeme in ["18446744073709551615", "1e+22", "1.0", "0.1"] {
            assert!(clean.contains(lexeme), "{lexeme} lost in {clean}");
        }
        let z = clean.find("\"z\"").unwrap();
        let a = clean.find("\"a\"").unwrap();
        assert!(z < a, "key order changed: {clean}");
    }

    #[test]
    fn json_escapes_duplicate_keys_and_order_survive_the_clean_path() {
        let clean = [
            r#"{"caf\u00e9":"cr\u00e8me","solidus":"a\/b"}"#,
            r#"{"dup":1,"dup":2,"last":3}"#,
            r#"{"z":1,"a":2,"m":3}"#,
            "{\n  \"pretty\": true,\n  \"indent\": [1, 2]\n}\n",
            r#"{"nested":"{\"n\":10000000000000000000000}"}"#,
        ];
        let home = Path::new("/definitely-not-the-home");
        for raw in clean {
            assert_eq!(redact_secrets(raw), raw, "rewritten: {raw}");
            assert_eq!(scrub_external_preview(home, raw, 1 << 20), raw);
        }
    }

    #[test]
    fn a_redacted_document_stays_semantically_identical() {
        // When something IS redacted, the changed region is re-serialised
        // compactly: whitespace normalises and escapes may normalise to
        // UTF-8, but keys keep input order, numbers keep their lexemes and
        // duplicate keys follow documented JSON semantics (last one wins).
        // Stated guarantee: byte-identical when clean, semantically identical
        // when redacted.
        let raw = "{\n  \"api_key\": \"CANARYSEM01abcdef\",\n  \"msg\": \"caf\\u00e9\",\n  \"dup\": 1,\n  \"dup\": 2,\n  \"n\": 1e+22\n}\n";
        let clean = redact_secrets(raw);
        assert!(!clean.contains("CANARYSEM01abcdef"), "{clean}");
        assert!(clean.contains("café"), "{clean}");
        assert!(clean.contains("1e+22"), "{clean}");
        assert_eq!(clean.matches("\"dup\"").count(), 1, "{clean}");
        assert!(clean.contains("\"dup\":2"), "{clean}");
        let api = clean.find("\"api_key\"").unwrap();
        let msg = clean.find("\"msg\"").unwrap();
        let n = clean.find("\"n\"").unwrap();
        assert!(api < msg && msg < n, "key order changed: {clean}");
        assert!(
            !clean.contains('\n'),
            "redacted document is compact: {clean}"
        );
    }

    #[test]
    fn a_zero_width_separator_is_stripped_before_redaction() {
        // B2-10: `token\u{200b}=…` is saved by `sanitize_text` on the shipped
        // path, even though the bare pattern redactor cannot see through the
        // invisible byte.
        let home = Path::new("/nonexistent-home");
        let raw = "token\u{200b}=CANARYE2EZWSP17";
        let clean = scrub_external_preview(home, raw, 4096);
        assert!(!clean.contains("CANARYE2EZWSP17"), "{clean}");
        let detail = sanitize_error_detail(home, raw, 512);
        assert!(!detail.contains("CANARYE2EZWSP17"), "{detail}");
    }

    /// dh-1 fidelity note: secret-free text keeps the four bidi isolate
    /// controls byte-for-byte — in prose and inside JSON — while an isolate
    /// that hides a secret is still consumed by the redaction.
    #[test]
    fn secret_free_text_keeps_bidi_isolates_but_they_cannot_hide_a_secret() {
        let home = Path::new("/definitely-not-the-home");
        let prose = "he said \u{2066}hello\u{2067}يا\u{2068}there\u{2069} ok";
        assert_eq!(redact_secrets(prose), prose, "prose was rewritten");
        assert_eq!(
            scrub_external_preview(home, prose, 1 << 20),
            prose,
            "preview was rewritten"
        );
        let json = "{\"msg\":\"mixed \u{2066}rtl\u{2069} text\",\"n\":1}";
        assert_eq!(redact_secrets(json), json, "json was rewritten");
        assert_eq!(
            scrub_external_preview(home, json, 1 << 20),
            json,
            "json preview was rewritten"
        );
        // A lone isolate is content too, but the other controls still go.
        assert_eq!(redact_secrets("\u{2067}"), "\u{2067}");
        assert_eq!(redact_secrets("\u{202e}"), "");

        // An isolate that breaks a heuristic pair (`access_token=…`) must
        // not shield the value from the redactor.
        let pair = "access_token\u{2067}=CANARYISOLATEHEUR1";
        let clean = scrub_external_preview(home, pair, 4096);
        assert!(!clean.contains("CANARYISOLATEHEUR1"), "{clean}");
    }

    #[test]
    fn prefix_matches_never_start_mid_word() {
        // B2-07: `task-sk-1234` used to be mangled at the `sk-` boundary.
        for raw in ["task-sk-1234", "disk-sk-usage", "risk-sk-1", "disk-usage"] {
            assert_eq!(redact_secrets(raw), raw, "mangled {raw}");
        }
        assert_eq!(
            redact_secrets("token sk-canary-abcdef123456 end"),
            "token sk-<redacted> end"
        );
    }

    #[test]
    fn code_and_hash_values_are_preserved() {
        // B2-08: six-byte assignment values used to be replaced
        // unconditionally.
        for raw in [
            "public_key_sha256 = 9f2a1b3c",
            "key = \"abcdefghijkl\"",
            "let token = parse(input);",
            "password: required",
            "token: None",
            "api_key= query parameter",
            "check_id=1234 and password=short",
        ] {
            assert_eq!(redact_secrets(raw), raw, "mangled {raw}");
        }
        // A real digest after a hash-only name is preserved too.
        let digest = "3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3";
        assert_eq!(
            redact_secrets(&format!("public_key_sha256={digest}")),
            format!("public_key_sha256={digest}")
        );
    }

    #[test]
    fn pem_labels_are_case_insensitive_and_putty_keys_are_covered() {
        // B2-06.
        let pem = "-----BEGIN private key-----\nCANARYPEM0005abcdefgh\n-----END private key-----";
        assert_eq!(
            redact_secrets(pem),
            "-----BEGIN private key-----<redacted>-----END private key-----"
        );
        let putty = format!(
            "PuTTY-User-Key-File-3: ssh-rsa\nPrivate-Lines: 2\n{}\nPrivate-MAC: x",
            "CANARYPUTTY0004abcdefgh"
        );
        let clean = redact_secrets(&putty);
        assert!(!clean.contains("CANARYPUTTY0004abcdefgh"), "{clean}");
        // A certificate is not a private key and stays readable.
        let cert = "-----BEGIN CERTIFICATE-----\nMIICcanaryCERT\n-----END CERTIFICATE-----";
        assert_eq!(redact_secrets(cert), cert);
    }

    #[test]
    fn aux_key_values_below_the_assignment_threshold_are_redacted() {
        // N02 pin (B2-12): the `AUX_KEY_` rule redacts any non-empty value,
        // independent of the generic assignment threshold and of whitespace
        // around the separator.
        assert_eq!(
            redact_secrets("export AUX_KEY_X = abcd"),
            "export AUX_KEY_X = <redacted>"
        );
        assert_eq!(redact_secrets("AUX_KEY_X=1"), "AUX_KEY_X=<redacted>");
        assert_eq!(
            redact_secrets("AUX_KEY_DEEPSEEK: CANARYE2EENV10"),
            "AUX_KEY_DEEPSEEK: <redacted>"
        );
    }

    // ---- round 5: brackets, padded keys, folded schemes, sibling pairs ----

    #[test]
    fn bracketed_values_are_redacted() {
        // B5-01: `(…)`/`<…>` are value delimiters, so the pair used to read
        // an empty value and the secret survived with no name in front of it.
        assert_eq!(
            redact_secrets("api_key=(CANARY_B5PAREN01)"),
            "api_key=(<redacted>)"
        );
        assert_eq!(
            redact_secrets("password=(mysecretpassphrase)"),
            "password=(<redacted>)"
        );
        assert_eq!(
            redact_secrets("api_key=<CANARY_B5ANGLE02>"),
            "api_key=<redacted>"
        );
        // Bracket prose without a credential name stays readable.
        assert_eq!(
            redact_secrets("the (secret) ingredient"),
            "the (secret) ingredient"
        );
        assert_eq!(redact_secrets("password=(short)"), "password=(short)");
        assert_eq!(redact_secrets("if (a) then (b)"), "if (a) then (b)");
        // The wrapper can span the line break a pretty-printer inserts.
        assert_eq!(
            redact_secrets("password=(\n  CANARY_B5WRAP03\n)"),
            "password=(\n  <redacted>\n)"
        );
    }

    #[test]
    fn padded_json_keys_are_classified_after_trim() {
        // B5-02: a single padding space inside the quotes switched both
        // layers off.
        let clean = redact_secrets(r#"{ " api_key " : "CANARY_B5PAD01" }"#);
        assert!(!clean.contains("CANARY_B5PAD01"), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        let clean = redact_secrets(r#"{" api_key ":"CANARY_B5PAD02"}"#);
        assert!(!clean.contains("CANARY_B5PAD02"), "{clean}");
        // Not JSON: the quoted-name rule skips the same padding.
        let clean = redact_secrets(r#"" api_key " = CANARY_B5PAD03"#);
        assert!(!clean.contains("CANARY_B5PAD03"), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        // An ordinary quoted phrase is untouched.
        assert_eq!(
            redact_secrets(r#"" a key point " and more"#),
            r#"" a key point " and more"#
        );
    }

    #[test]
    fn folded_scheme_credentials_are_redacted() {
        // B5-04: `Bearer`/`Basic` only accepted a space or tab before the
        // value, so an obs-folded credential leaked verbatim.
        assert_eq!(
            redact_secrets("Bearer\n abcdefghijklmnopqrst"),
            "Bearer\n <redacted>"
        );
        let clean = redact_secrets("Basic\n YWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert!(!clean.contains("YWxhZGRpbjpvcGVuIHNlc2FtZQ"), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        let clean = redact_secrets("Authorization: Bearer\r\n  CANARY_B5FOLD04abcdefghij");
        assert!(!clean.contains("CANARY_B5FOLD04abcdefghij"), "{clean}");
        // `Bearer bonds` is prose, not a credential.
        assert_eq!(
            redact_secrets("The Bearer bonds are up"),
            "The Bearer bonds are up"
        );
    }

    #[test]
    fn sibling_name_value_pairs_are_redacted() {
        // E5-01: the credential name and its value in separate entries
        // defeated both layers; tool-call dumps, MCP envelopes and
        // credential managers produce exactly these shapes.
        let cases: &[&str] = &[
            r#"{"name":"api_key","value":"CANARY_E5PAIR01"}"#,
            r#"{"key":"api_key","value":"CANARY_E5PAIR02"}"#,
            r#"{"field":"password","content":"CANARY_E5PAIR03"}"#,
            r#"{"variable":"DB_PASSWORD","val":"CANARY_E5PAIR04"}"#,
            r#"{"arguments":{"name":"api_key","value":"CANARY_E5PAIR05"}}"#,
            r#"["api_key","CANARY_E5PAIR06"]"#,
            r#"["Authorization","Bearer CANARY_E5PAIR07"]"#,
            r#"["Cookie","sid=CANARY_E5PAIR08"]"#,
        ];
        for raw in cases {
            let clean = redact_secrets(raw);
            assert!(
                !clean.contains("CANARY_E5PAIR"),
                "leaked in {clean:?} (from {raw})"
            );
        }
        // A non-credential name leaves its sibling alone.
        assert_eq!(
            redact_secrets(r#"{"name":"agent-name","value":"main"}"#),
            r#"{"name":"agent-name","value":"main"}"#
        );
        assert_eq!(redact_secrets(r#"["key","value"]"#), r#"["key","value"]"#);
    }

    #[test]
    fn environment_carriers_bracket_names_and_short_pass_names_are_redacted() {
        // E6-01: tool-call dumps use `env`/`var`/`setting`/`option`/`param`
        // as the name carrier next to a value carrier; E6-04: PHP/Rails
        // bracket query names, `DB_PASS`/`PASSWD`/`PW` and short `pass=`/
        // `pw=` query names.
        let cases: &[&str] = &[
            r#"{"env":"DB_PASSWORD","value":"CANARY_E6ENV01abcdef"}"#,
            r#"{"var":"api_key","value":"CANARY_E6VAR02abcdef"}"#,
            r#"{"setting":"password","value":"CANARY_E6SET03abcdef"}"#,
            r#"{"option":"token","value":"CANARY_E6OPT04abcdef"}"#,
            r#"{"param":"secret","value":"CANARY_E6PAR05abcdef"}"#,
            "export DB_PASS=CANARY_E6PASS06abcdef",
            "MYSQL_PASSWD=CANARY_E6PASSWD07abcdef",
            "DB_PW=CANARY_E6PW08abcdef",
            "/login?auth[token]=CANARY_E6QRY09abcdef",
            "/login?token[]=CANARY_E6QRY10abcdef",
            "/login?pass=CANARY_E6QRY11abcdef",
            "/login?pw=CANARY_E6QRY12abcdef",
        ];
        for raw in cases {
            let clean = redact_secrets(raw);
            assert!(
                clean.contains("<redacted>"),
                "no marker in {clean:?} from {raw:?}"
            );
            assert!(
                !clean.contains("CANARY_E6"),
                "leaked in {clean:?} from {raw:?}"
            );
        }
        // Ordinary text with the same words stays readable.
        assert_eq!(
            redact_secrets("the env variable overview"),
            "the env variable overview"
        );
        assert_eq!(redact_secrets("pass = required"), "pass = required");
        assert_eq!(redact_secrets("pw = 1"), "pw = 1");
        assert_eq!(redact_secrets("bypass = true"), "bypass = true");
        assert_eq!(
            redact_secrets(r#"{"env":"PATH","value":"/usr/bin"}"#),
            r#"{"env":"PATH","value":"/usr/bin"}"#
        );
    }

    #[test]
    fn json5_comments_and_percent_separators_are_transparent() {
        // B5-05/E6-03: a comment before or after the separator.
        assert_eq!(
            redact_secrets("api_key /* c */ = CANARY_E6COM01abcdef"),
            "api_key /* c */ = <redacted>"
        );
        let clean = redact_secrets(r#"{ "api_key": /* c */ "CANARY_E6COM02abcdef" }"#);
        assert!(!clean.contains("CANARY_E6COM02abcdef"), "{clean}");
        assert!(clean.contains("<redacted>"), "{clean}");
        let clean = redact_secrets("api_key: // c\n CANARY_E6COM03abcdef");
        assert!(!clean.contains("CANARY_E6COM03abcdef"), "{clean}");
        // SB6-04: percent-encoded whitespace around the separator and a
        // doubled separator.
        assert_eq!(
            redact_secrets("api_key%20=%20CANARY_E6PCT04abcdef"),
            "api_key%20=%20<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key = = CANARY_E6SEP05abcdef"),
            "api_key = = <redacted>"
        );
        // Non-credential names and protocol-relative values stay readable.
        assert_eq!(redact_secrets("price /* c */ = 12"), "price /* c */ = 12");
        assert_eq!(
            redact_secrets("homepage_url=//example.com/x"),
            "homepage_url=//example.com/x"
        );
    }

    #[test]
    fn bracketed_dash_flags_and_scheme_values_are_redacted() {
        // E6-05/E6-06: the B5-01 bracket rule now covers `curl --user`/
        // `--password` and `Bearer`/`Basic`, which used to leak verbatim.
        assert_eq!(
            redact_secrets("curl --user=(admin:CANARY_E6DASH01abcdef) https://x"),
            "curl --user=(<redacted>) https://x"
        );
        assert_eq!(
            redact_secrets("curl --password=<CANARY_E6DASH02abcdef> https://x"),
            "curl --password=<redacted> https://x"
        );
        assert_eq!(
            redact_secrets("Bearer (CANARY_E6BEAR03abcdefghij)"),
            "Bearer (<redacted>)"
        );
        assert_eq!(
            redact_secrets("Basic (<CANARY_E6BASIC04abcdefg>)"),
            "Basic (<redacted>)"
        );
        // Prose with brackets stays readable.
        assert_eq!(redact_secrets("--user (me)"), "--user (me)");
        assert_eq!(redact_secrets("Bearer (bonds)"), "Bearer (bonds)");
    }

    #[test]
    fn numeric_json_values_under_secret_names_are_redacted() {
        // B5-03: an 18-digit key under `api_key` used to survive the JSON
        // walk; epoch/counter-shaped numbers stay readable.
        assert_eq!(
            redact_secrets(r#"{"api_key":123456789012345678}"#),
            r#"{"api_key":"<redacted>"}"#
        );
        let clean = redact_secrets(r#"{"password":12345678901234567890}"#);
        assert!(!clean.contains("12345678901234567890"), "{clean}");
        assert_eq!(
            redact_secrets(r#"{"token":1699999999999}"#),
            r#"{"token":1699999999999}"#
        );
        assert_eq!(redact_secrets(r#"{"port":5432}"#), r#"{"port":5432}"#);
    }

    #[test]
    fn separator_lookalikes_fold_only_next_to_a_credential_name() {
        // B3-04 stays fixed (all four aliases) while B5-07's whole-block
        // rewrite is gone.
        assert_eq!(
            redact_secrets("api_key＝CANARY_E5FULL01"),
            "api_key=<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key：CANARY_E5FULL02"),
            "api_key:<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key﹕CANARY_E5FULL03"),
            "api_key:<redacted>"
        );
        assert_eq!(
            redact_secrets("api_key﹦CANARY_E5FULL04"),
            "api_key=<redacted>"
        );
        assert_eq!(redact_secrets("price＝100"), "price＝100");
        assert_eq!(redact_secrets("全角記号：ＡＢＣ"), "全角記号：ＡＢＣ");
    }

    #[test]
    fn typography_cjk_and_fullwidth_text_survive_byte_for_byte() {
        // B5-07/H-05: the normalise layer used to fold U+FF01–U+FF5E and all
        // curly quotes on every pass, silently rewriting ordinary prose on
        // every surface. Only a separator directly after a credential name
        // is folded now.
        let home = Path::new("/definitely-not-the-home");
        let prose = [
            "He said “hello” and don’t stop — really…",
            "简体中文、，。！？；：（）《》",
            "全角記号：ＡＢＣ－ＸＹＺ，！？",
            "価格：100円！重要",
            "ok 👍 done 🎉 shipped 🚀",
            "CJK comma 、 and full stop 。",
            "مرحبا بالعالم",
            "price＝100 and ratio：0.5",
        ];
        for raw in prose {
            assert_eq!(redact_secrets(raw), raw, "redact_secrets rewrote {raw}");
            assert_eq!(
                scrub_external_preview(home, raw, 1 << 20),
                raw,
                "preview rewrote {raw}"
            );
            assert_eq!(
                sanitize_error_detail(home, raw, 4096),
                raw,
                "detail rewrote {raw}"
            );
        }
    }

    #[test]
    fn serde_json_arbitrary_precision_features_stay_workspace_unified() {
        // H-11: `arbitrary_precision` + `preserve_order` unify across the
        // whole workspace (kernel-broker/Cargo.toml): the structured scrub keeps
        // each number's original lexeme and each key's input order even when
        // a sibling is redacted. The historical sharp edge is a numeric
        // field under `#[serde(flatten)]`/untagged: with `arbitrary_precision`
        // an older serde_json could not deserialize it, and a future numeric
        // field would have failed silently at runtime. The three current
        // flatten/untagged call sites (the daemon snapshot/agents,
        // the app's providers crate openai_compat) carry no numeric fields; this pin
        // proves numbers are handled today and makes the failure mode loud if
        // that changes.
        #[derive(serde::Deserialize, Debug)]
        struct TypedFlatten {
            name: String,
            #[serde(flatten)]
            extra: std::collections::BTreeMap<String, u64>,
        }
        let typed: TypedFlatten = serde_json::from_str(r#"{"name":"x","count":3}"#)
            .expect("flattened numbers must deserialize under arbitrary_precision");
        assert_eq!(typed.name, "x");
        assert_eq!(typed.extra.get("count"), Some(&3));

        #[derive(serde::Deserialize, Debug)]
        #[serde(untagged)]
        enum Untagged {
            Pair { name: String, count: u64 },
        }
        let untagged: Untagged = serde_json::from_str(r#"{"name":"x","count":3}"#)
            .expect("untagged numbers must deserialize under arbitrary_precision");
        match untagged {
            Untagged::Pair { name, count } => {
                assert_eq!(name, "x");
                assert_eq!(count, 3);
            }
        }

        // And the structured layer keeps every lexeme of such a document.
        let raw = r#"{"name":"x","count":18446744073709551615,"ratio":1e+22}"#;
        assert_eq!(redact_secrets(raw), raw);
    }

    #[test]
    #[ignore = "timing test: run alone with --ignored --test-threads=1"]
    fn redaction_is_linear_on_every_adversarial_shape() {
        // B2-04/P3-7 + round 3: 42 adversarial shapes at 256 KiB must each
        // stay linear. The old JWT scan was quadratic on repeated `eyJ`
        // (159 s at 256 KiB); the structured pass must not reintroduce it.
        const SIZE: usize = 256 * 1024;
        let shapes = |size: usize| -> Vec<(&'static str, String)> {
            vec![
                ("jwt-prefix", "eyJ".repeat(size / 3)),
                ("assignment-eq", "a=".repeat(size / 2)),
                ("token-ab", "token=ab ".repeat(size / 9)),
                ("vendor-sk", "sk-".repeat(size / 3)),
                ("vendor-nested", "sk-sk-".repeat(size / 6)),
                ("aux-key", "AUX_KEY_X=ab ".repeat(size / 12)),
                (
                    "authorization-none",
                    "authorization: none\n".repeat(size / 20),
                ),
                ("bearer-words", "Bearer bonds ".repeat(size / 13)),
                ("cert", "-----BEGIN CERTIFICATE-----\n".repeat(size / 28)),
                (
                    "pem-label",
                    "-----BEGIN private key-----\n".repeat(size / 29),
                ),
                (
                    "pem-open",
                    format!("-----BEGIN private key-----\n{}", "x".repeat(size)),
                ),
                ("putty", "PuTTY-User-Key-File-3:".repeat(size / 23)),
                ("base64", "aGVsbG8=\n".repeat(size / 9)),
                ("nested-quotes", "\"a\\\"b\\\"c\" ".repeat(size / 10)),
                ("long-line", "a".repeat(size)),
                ("quotes-only", "\"".repeat(size)),
                ("backslashes", "\\".repeat(size)),
                ("equals-only", "=".repeat(size)),
                ("colons-only", ":".repeat(size)),
                ("dashes", "-".repeat(size)),
                ("schemes", "://".repeat(size / 3)),
                ("unicode-zwsp", "a\u{200b}=b ".repeat(size / 7)),
                ("url-userinfo", "postgres://u:pass@h/d ".repeat(size / 21)),
                ("url-noat-long", format!("postgres://{}", "a".repeat(size))),
                ("json-array", "[\"abcdef\",".repeat(size / 10)),
                (
                    "json-nested",
                    format!("{}1{}", "[".repeat(2000), "]".repeat(2000)),
                ),
                (
                    "json-deep-obj",
                    format!("{}\"a\":1{}", "{\"a\":".repeat(800) + "{", "}".repeat(801)),
                ),
                (
                    "json-pretty-multiline",
                    "{\n  \"api_key\":\n    \"abcdef123456\"\n}\n".repeat(size / 36),
                ),
                (
                    "json-escaped-quotes",
                    "{\"a\":\"b\\\"c\"},".repeat(size / 15),
                ),
                ("percent-sep", "api_key%3Dabcdef123456 ".repeat(size / 22)),
                ("quoted-token", "\"token\":\"abcdef\",".repeat(size / 19)),
                ("colon-pair", "api_key: abcdef123456 ".repeat(size / 21)),
                ("cookie-header", "Cookie: a=1; b=2\n".repeat(size / 17)),
                (
                    "cookie-header-blank",
                    format!("Cookie:{}", " ".repeat(size)),
                ),
                ("semicolons", ";".repeat(size)),
                ("commas", ",".repeat(size)),
                ("long-line-spaces", " ".repeat(size)),
                (
                    "percent-url",
                    "postgres%3A%2F%2Fu:pass@h/d ".repeat(size / 25),
                ),
                ("fullwidth-sep", "api_key＝abcdef ".repeat(size / 18)),
                (
                    "json-in-json",
                    "{\"detail\":\"{\\\"api_key\\\":\\\"abcdef123456\\\"}\"},".repeat(size / 43),
                ),
                (
                    "cookie-jar",
                    "session=abcdef123456; Path=/; HttpOnly\n".repeat(size / 37),
                ),
                (
                    "mixed-randomish",
                    [
                        "token=ab ",
                        "api_key%3Dabcdef ",
                        "\"token\":\"abcdef\",",
                        "postgres://u:pass@h/d ",
                        "Cookie: a=1; b=2\n",
                        "{\"a\":\"b\\\"c\"},",
                        "session=abcdef123456; ",
                        "Bearer bonds ",
                        "-----BEGIN CERTIFICATE-----\n",
                        "a\u{200b}=b ",
                    ]
                    .iter()
                    .cycle()
                    .take(size / 20)
                    .copied()
                    .collect::<String>(),
                ),
                // --- round 5: the new shapes are all bounded, one pass each ---
                (
                    "bracket-values",
                    "api_key=(abcdef123456) ".repeat(size / 23),
                ),
                (
                    "padded-json-key",
                    "{\" api_key \":\"abcdef123456\"},".repeat(size / 29),
                ),
                (
                    "folded-bearer",
                    "Bearer\n abcdefghijklmnopqrst ".repeat(size / 29),
                ),
                (
                    "sibling-pairs",
                    "{\"name\":\"api_key\",\"value\":\"abcdef123456\"},".repeat(size / 45),
                ),
                (
                    "fullwidth-prose",
                    "全角記号：ＡＢＣ－ＸＹＺ，！？ 简体中文、，。".repeat(size / 65),
                ),
            ]
        };
        assert_eq!(
            shapes(SIZE).len(),
            47,
            "the 47-shape cost table is the contract"
        );
        // Linear means 4x the input costs about 4x the time; quadratic costs
        // 16x. Compare each shape at n and 4n, not against a wall-clock budget
        // that flakes when the machine is loaded. The hang guard is only for
        // a true blow-up.
        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(30);
        fn best_of_three(label: &str, text: &str) -> std::time::Duration {
            (0..3)
                .map(|_| {
                    let started = std::time::Instant::now();
                    let _ = redact_secrets(text);
                    let elapsed = started.elapsed();
                    assert!(
                        elapsed < HANG_GUARD,
                        "{label}: redaction took {elapsed:?} on {} bytes (hang guard {HANG_GUARD:?})",
                        text.len()
                    );
                    elapsed
                })
                .min()
                .unwrap_or_default()
        }
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
        // The shape that used to be quadratic, at its own size.
        let mut pem = String::from("-----BEGIN private key-----\n");
        pem.push_str(&"x".repeat(SIZE));
        let started = std::time::Instant::now();
        assert!(!redact_secrets(&pem).contains(&"x".repeat(64)));
        assert!(
            started.elapsed() < HANG_GUARD,
            "private PEM block took {:?} (hang guard {HANG_GUARD:?})",
            started.elapsed()
        );
    }

    /// FAKE: values invented for the tests, never a real person's.
    const TITLE_VALUES: [(&str, &str); 2] = [
        ("lena.ortiz@example.org", "lena"),
        ("FR76 3000 6000 0112 3456 7890 189", "FR76"),
    ];

    #[test]
    fn title_detects_values_at_every_display_boundary() {
        for boundary in [47, 60, 186, 200, 400] {
            for (value, marker) in TITLE_VALUES {
                let text = format!("{} {value}", "x".repeat(boundary));
                let title = scrub_title(&text);
                assert!(
                    !title.contains(marker),
                    "boundary {boundary}: {title:?} leaked {marker}"
                );
                assert!(
                    title.chars().count() <= 200,
                    "boundary {boundary}: {} chars",
                    title.chars().count()
                );
            }
        }
    }

    #[test]
    fn title_scan_cap_drops_a_run_it_would_cut() {
        for (value, marker) in TITLE_VALUES {
            // No whitespace around the value: the 400-character scan would end
            // inside it, so the whole run must be dropped.
            let title = scrub_title(&format!("{}{value}", "x".repeat(395)));
            assert!(title.ends_with('…'), "{title:?}");
            assert!(!title.contains(marker), "{title:?} leaked {marker}");

            // A run that begins after the last space is dropped whole too.
            let title = scrub_title(&format!("{} {value}", "x".repeat(390)));
            assert!(title.ends_with('…'), "{title:?}");
            assert!(!title.contains(marker), "{title:?} leaked {marker}");
        }
    }

    #[test]
    fn display_scrub_detects_a_value_on_a_later_line() {
        assert_eq!(
            scrub_display_text("Hello\nlena.ortiz@example.org", 4096),
            "Hello\n[e-mail]"
        );
    }
}
