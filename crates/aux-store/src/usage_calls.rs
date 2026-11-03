//! Per-call brain usage (INFER-COST-1): fresh, cached and output tokens of
//! each provider call. Counts and names only, never a prompt or a reply.

use crate::{Store, StoreError};

/// v28: one row per brain call. `NULL` counts mean the provider did not report them.
pub(crate) const MIGRATION_V28: &str = r#"
CREATE TABLE IF NOT EXISTS usage_calls (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    at                TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    run_id            TEXT,
    agent             TEXT NOT NULL,
    provider          TEXT NOT NULL,
    model             TEXT,
    call_index        INTEGER NOT NULL,
    prompt_tokens     INTEGER,
    cached_tokens     INTEGER,
    completion_tokens INTEGER
);
CREATE INDEX IF NOT EXISTS idx_usage_calls_at ON usage_calls(at);
"#;

/// Placeholder for a key-shaped provider name in `usage_calls`.
pub(crate) const HIDDEN_PROVIDER: &str = "[hidden]";

/// v34: replace key-shaped provider names written by older versions.
///
/// The detector is the shared kernel-broker classifier (raw and every
/// percent-decoded copy), run in Rust because SQL cannot decode them.
pub(crate) fn hide_key_shaped_providers(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<usize> {
    let mut stmt = tx.prepare("SELECT DISTINCT provider FROM usage_calls")?;
    let providers: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    let mut changed = 0;
    for provider in providers {
        if kernel_broker::is_secret_shaped(&provider) {
            changed += tx.execute(
                "UPDATE usage_calls SET provider = ?1 WHERE provider = ?2",
                rusqlite::params![HIDDEN_PROVIDER, provider],
            )?;
        }
    }
    Ok(changed)
}

/// One brain call as the provider reported it. `None` = not reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageCall<'a> {
    pub run_id: Option<&'a str>,
    pub agent: &'a str,
    pub provider: &'a str,
    pub model: Option<&'a str>,
    /// 1-based position of the call within its turn.
    pub call_index: u32,
    pub prompt_tokens: Option<u64>,
    pub cached_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
}

/// One day's brain calls, summed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageCallTotals {
    pub calls: u64,
    /// Distinct turns, and the most calls one of them made.
    pub turns: u64,
    pub max_call_index: u64,
    pub prompt_tokens: u64,
    pub cached_tokens: u64,
    /// Prompt tokens of the calls that reported a cache count (the hit-% base).
    pub cache_reported_prompt_tokens: u64,
    pub completion_tokens: u64,
}

impl UsageCallTotals {
    /// Cached share of the input, over the calls that reported one.
    pub fn cache_hit_percent(&self) -> Option<f64> {
        (self.cache_reported_prompt_tokens > 0)
            .then(|| 100.0 * self.cached_tokens as f64 / self.cache_reported_prompt_tokens as f64)
    }
}

fn count(value: Option<u64>) -> Option<i64> {
    value.map(|value| i64::try_from(value).unwrap_or(i64::MAX))
}

impl Store {
    /// Record one brain call's token counts.
    pub fn record_usage_call(&self, call: &UsageCall<'_>) -> Result<(), StoreError> {
        crate::validate_usage_agent(call.agent)?;
        let provider = if kernel_broker::is_secret_shaped(call.provider) {
            HIDDEN_PROVIDER
        } else {
            call.provider
        };
        self.conn.execute(
            "INSERT INTO usage_calls(run_id, agent, provider, model, call_index,
                                     prompt_tokens, cached_tokens, completion_tokens)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                call.run_id,
                call.agent,
                provider,
                call.model,
                call.call_index,
                count(call.prompt_tokens),
                count(call.cached_tokens),
                count(call.completion_tokens),
            ],
        )?;
        Ok(())
    }

    /// The brain calls of the local day `day` (`YYYY-MM-DD`), for one agent or all.
    pub fn usage_call_totals(
        &self,
        agent: Option<&str>,
        day: &str,
    ) -> Result<UsageCallTotals, StoreError> {
        let row = self.conn.query_row(
            "SELECT COUNT(*), COUNT(DISTINCT run_id), COALESCE(MAX(call_index), 0),
                    COALESCE(SUM(prompt_tokens), 0), COALESCE(SUM(cached_tokens), 0),
                    COALESCE(SUM(CASE WHEN cached_tokens IS NOT NULL THEN prompt_tokens END), 0),
                    COALESCE(SUM(completion_tokens), 0)
             FROM usage_calls
             WHERE at >= ?1 AND at < date(?1, '+1 day') AND (?2 IS NULL OR agent = ?2)",
            rusqlite::params![day, agent],
            |row| {
                (0..7)
                    .map(|i| row.get::<_, i64>(i))
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        let n = |i: usize| row[i].max(0) as u64;
        Ok(UsageCallTotals {
            calls: n(0),
            turns: n(1),
            max_call_index: n(2),
            prompt_tokens: n(3),
            cached_tokens: n(4),
            cache_reported_prompt_tokens: n(5),
            completion_tokens: n(6),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn providers(store: &Store) -> Vec<String> {
        let mut stmt = store
            .conn
            .prepare("SELECT provider FROM usage_calls ORDER BY id")
            .unwrap();
        stmt.query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn a_key_shaped_provider_is_stored_as_the_placeholder() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_usage_call(&UsageCall {
                agent: "main",
                provider: "sk-proj-canary-7f3k9q",
                call_index: 1,
                ..UsageCall::default()
            })
            .unwrap();
        store
            .record_usage_call(&UsageCall {
                agent: "main",
                provider: "deepseek",
                call_index: 2,
                ..UsageCall::default()
            })
            .unwrap();
        assert_eq!(providers(&store), [HIDDEN_PROVIDER, "deepseek"]);
    }
}
