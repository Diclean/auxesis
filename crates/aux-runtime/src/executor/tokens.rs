//! Token restore: rehydrate the session's masked values before a send, and mask
//! a connector result again before the model sees it.
//!
//! Moved here unchanged from `executor.rs`; the parent re-exports the public
//! items, so `aux_runtime::executor::{TokenResolver, restore_value,
//! retokenize_value}` still resolve.

use kernel_privacy::{LinkGuard, TokenMap, PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use serde_json::{Map, Value};

/// The session's token ↔ value view, as the executor needs it.
///
/// The session tokens are memory-only per session today (the gate's key is a
/// process-lifetime root), so the executor takes this interface rather than a
/// [`TokenMap`], whose constructors the kernel keeps private. A resolver answers
/// only for its own session: a token minted elsewhere resolves to `None`, and
/// the run is refused.
pub trait TokenResolver: Send + Sync {
    /// The value `token` stands for, or `None` when it is unknown here.
    fn resolve(&self, token: &str) -> Option<String>;

    /// Every `(token, value)` pair known here, for re-tokenising a result.
    fn pairs(&self) -> Vec<(String, String)>;
}

/// A vault map is a resolver for exactly one session.
impl TokenResolver for TokenMap {
    fn resolve(&self, token: &str) -> Option<String> {
        self.iter()
            .find(|(known, _)| known == token)
            .map(|(_, value)| value.clone())
    }

    fn pairs(&self) -> Vec<(String, String)> {
        self.iter().cloned().collect()
    }
}

/// Restore every token in a JSON value, refusing the whole run on any token
/// that does not resolve.
///
/// The unknown policy is the kernel's strictest: an unresolved token becomes
/// `[unknown reference]`, never the token in the clear, and the run is refused.
/// A value that still contains `⟦`/`⟧` after restore is refused too.
pub fn restore_value(value: &Value, tokens: &dyn TokenResolver) -> Result<Value, String> {
    match value {
        Value::String(text) => Ok(Value::String(restore_text(text, tokens)?)),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(restore_value(item, tokens)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            // Keys are restored too: a token smuggled into a key is refused the
            // same way one in a value is.
            let mut out = Map::with_capacity(map.len());
            for (key, item) in map {
                out.insert(restore_text(key, tokens)?, restore_value(item, tokens)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

/// Restore one string, mirroring the kernel's parser: `⟦⟦` is a literal
/// opener, `⟦⟧` is kept, a missing closer makes every later `⟦` ordinary text,
/// and an unresolved token is counted and refused.
fn restore_text(text: &str, tokens: &dyn TokenResolver) -> Result<String, String> {
    let mut restored = String::with_capacity(text.len());
    let mut unknown = 0usize;
    let mut cursor = 0usize;
    let mut no_close = false;
    let mut links = LinkGuard::default();
    while cursor < text.len() {
        let ch = text[cursor..]
            .chars()
            .next()
            .expect("cursor is a char boundary");
        if ch == PLACEHOLDER_OPEN
            && text[cursor + PLACEHOLDER_OPEN.len_utf8()..].starts_with(PLACEHOLDER_OPEN)
        {
            // `⟦⟦` is the literal opener `anonymize` wrote doubled.
            links.append_to(&mut restored, "⟦");
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
                        links.append_to(
                            &mut restored,
                            &text[cursor..inner_end + PLACEHOLDER_CLOSE.len_utf8()],
                        );
                    } else if let Some(value) = tokens.resolve(token) {
                        if !links
                            .append_token_value(
                                &mut restored,
                                token,
                                &value,
                                &text[inner_end + PLACEHOLDER_CLOSE.len_utf8()..],
                                true,
                            )
                            .unwrap_or(true)
                        {
                            links.append_to(&mut restored, &value);
                        }
                    } else {
                        unknown += 1;
                        links.append_to(&mut restored, kernel_privacy::UNKNOWN_REFERENCE);
                    }
                    cursor = inner_end + PLACEHOLDER_CLOSE.len_utf8();
                }
                None => {
                    no_close = true;
                    links.append_to(&mut restored, "⟦");
                    cursor = inner_start;
                }
            }
        } else {
            links.append_to(&mut restored, &text[cursor..cursor + ch.len_utf8()]);
            cursor += ch.len_utf8();
        }
    }
    links.finish(&mut restored);
    let kept_in_link = links.take_redactions();
    if kept_in_link > 0 {
        tracing::info!(kept_in_link, "link values kept hidden");
    }
    if unknown > 0 {
        // The model reads this: say the tool works and what to send instead,
        // so it retries the same tool rather than hunting the data elsewhere.
        return Err(format!(
            "the call did not run and wrote nothing: {unknown} name token(s) in the arguments \
             did not resolve in this conversation. The tool itself works: retry with the token \
             copied exactly as the owner wrote it, or with a plain word"
        ));
    }
    if restored.contains(PLACEHOLDER_OPEN) || restored.contains(PLACEHOLDER_CLOSE) {
        return Err(
            "the call did not run: a value still contains a ⟦…⟧ delimiter; \
                    retry with plain text. The tool itself works"
                .to_string(),
        );
    }
    Ok(restored)
}

/// Replace every real value in a connector result with its token, so the result
/// can re-enter the model conversation.
pub fn retokenize_value(value: &Value, tokens: &dyn TokenResolver) -> Value {
    match value {
        Value::String(text) => Value::String(retokenize_text(text, tokens)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| retokenize_value(item, tokens))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), retokenize_value(item, tokens)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Replace every real value in `text` with `⟦token⟧`. Longest values first, so
/// a value that contains another is still replaced whole.
fn retokenize_text(text: &str, tokens: &dyn TokenResolver) -> String {
    let mut pairs: Vec<(String, String)> = tokens.pairs();
    pairs.sort_by_key(|(_, value)| std::cmp::Reverse(value.len()));
    let mut out = text.to_string();
    for (token, value) in pairs {
        if value.is_empty() {
            continue;
        }
        out = out.replace(
            &value,
            &format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}"),
        );
    }
    out
}
