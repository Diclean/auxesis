//! `aux stop`, `aux resume` and `aux usage` — the kill switch and the
//! usage meter of the per-agent budgets.
//!
//! `stop`/`resume` only toggle the `~/.auxesis/STOP` marker; the always-on
//! components (`auxd`, jobs, notifications) check it before each step.
//! `usage` reads the `usage` meter (v5 schema, day-bounded) and prints a day
//! summary — it never mutates anything.

use aux_store::Store;
use clap::Args;
use kernel_core::{auxesis_home, ensure_home, killswitch, UsageTotals};
use std::io::Write;
use std::process::ExitCode;

/// Arguments of `aux usage`.
#[derive(Debug, Args)]
pub struct UsageArgs {
    /// Only show usage for this agent.
    #[arg(long, value_name = "AGENT")]
    pub agent: Option<String>,
    /// Local day to summarize (`YYYY-MM-DD`, default: today).
    #[arg(long, value_name = "YYYY-MM-DD")]
    pub day: Option<String>,
}

/// Run `aux stop`: engage the kill switch.
pub fn run_stop() -> ExitCode {
    let home = auxesis_home();
    match killswitch::engage(&home) {
        Ok(()) => {
            let _ = writeln!(
                std::io::stdout(),
                "kill switch engaged: {}",
                killswitch::stop_path(&home).display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux stop: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Run `aux resume`: release the kill switch (idempotent).
pub fn run_resume() -> ExitCode {
    let home = auxesis_home();
    match killswitch::release(&home) {
        Ok(true) => {
            let _ = writeln!(std::io::stdout(), "kill switch released");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            let _ = writeln!(std::io::stdout(), "kill switch was not engaged");
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux resume: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Run `aux usage`, printing errors to stderr and mapping them to the exit code.
pub fn run_usage(args: UsageArgs) -> ExitCode {
    match run_usage_inner(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux usage: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_usage_inner(args: UsageArgs) -> Result<(), String> {
    // The store opens through the verified handle only.
    let home = auxesis_home();
    let verified =
        ensure_home(&home).map_err(|err| format!("creating {}: {err}", home.display()))?;
    let store = Store::open_verified(&verified).map_err(|err| err.to_string())?;

    let day = match args.day {
        Some(day) => {
            validate_day(&day)?;
            if !store.valid_day(&day).map_err(|err| err.to_string())? {
                return Err(format!("invalid --day `{day}`: no such calendar date"));
            }
            day
        }
        None => store.local_day().map_err(|err| err.to_string())?,
    };

    let mut stdout = std::io::stdout();
    render_usage(&store, args.agent.as_deref(), &day, &mut stdout)
}

/// Reject `--day` values that are not plain `YYYY-MM-DD` dates.
fn validate_day(day: &str) -> Result<(), String> {
    let bytes = day.as_bytes();
    let shaped = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit());
    if !shaped {
        return Err(format!("invalid --day `{day}`: expected YYYY-MM-DD"));
    }
    Ok(())
}

/// Write the day summary: one line per agent, plus a total when scanning all.
fn render_usage(
    store: &Store,
    agent: Option<&str>,
    day: &str,
    out: &mut impl Write,
) -> Result<(), String> {
    writeln!(out, "usage {day}").map_err(|err| err.to_string())?;

    match agent {
        Some(agent) => {
            let totals = store
                .usage_totals(agent, day)
                .map_err(|err| err.to_string())?;
            writeln!(out, "{agent} {}", format_totals(&totals)).map_err(|err| err.to_string())?;
        }
        None => {
            let agents = store.usage_agents(day).map_err(|err| err.to_string())?;
            if agents.is_empty() {
                writeln!(out, "(no usage recorded)").map_err(|err| err.to_string())?;
            } else {
                let mut total = UsageTotals::default();
                for agent in agents {
                    let totals = store
                        .usage_totals(&agent, day)
                        .map_err(|err| err.to_string())?;
                    total.tokens_in += totals.tokens_in;
                    total.tokens_out += totals.tokens_out;
                    total.usd_cents += totals.usd_cents;
                    writeln!(out, "{agent} {}", format_totals(&totals))
                        .map_err(|err| err.to_string())?;
                }
                writeln!(out, "total {}", format_totals(&total)).map_err(|err| err.to_string())?;
            }
        }
    }
    // Brain calls and the share of their input the provider's cache served.
    let calls = store
        .usage_call_totals(agent, day)
        .map_err(|err| err.to_string())?;
    if calls.calls > 0 {
        let hit = calls
            .cache_hit_percent()
            .map_or_else(|| "n/a".to_string(), |hit| format!("{hit:.1}%"));
        writeln!(
            out,
            "calls={} turns={} max_per_turn={} prompt={} cached={} cache_hit={hit} completion={}",
            calls.calls,
            calls.turns,
            calls.max_call_index,
            calls.prompt_tokens,
            calls.cached_tokens,
            calls.completion_tokens
        )
        .map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn format_totals(totals: &UsageTotals) -> String {
    format!(
        "tokens_in={} tokens_out={} usd_cents={}",
        totals.tokens_in, totals.tokens_out, totals.usd_cents
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_core::UsageKind;

    #[test]
    fn validate_day_accepts_only_calendar_shaped_dates() {
        assert!(validate_day("2026-10-03").is_ok());
        for bad in [
            "",
            "2026-1-3",
            "03/10/2026",
            "2026-10-03T00:00",
            "20261003",
            "abcd-ef-gh",
        ] {
            assert!(validate_day(bad).is_err(), "`{bad}` should be rejected");
        }
    }

    #[test]
    fn render_usage_for_one_agent_reports_zeros_when_empty() {
        let store = Store::open_in_memory().unwrap();
        let mut out = Vec::new();
        render_usage(&store, Some("main"), "2026-10-03", &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "usage 2026-10-03\nmain tokens_in=0 tokens_out=0 usd_cents=0\n"
        );
    }

    #[test]
    fn render_usage_scans_all_agents_and_totals_them() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                10,
                "tokens",
                "2026-10-03 08:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::TokensOut,
                2,
                "tokens",
                "2026-10-03 08:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "axis",
                UsageKind::UsdCents,
                5,
                "cents",
                "2026-10-03 09:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "axis",
                UsageKind::TokensIn,
                1,
                "tokens",
                "2026-10-02 09:00:00",
            )
            .unwrap();

        let mut out = Vec::new();
        render_usage(&store, None, "2026-10-03", &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "usage 2026-10-03\n\
             axis tokens_in=0 tokens_out=0 usd_cents=5\n\
             main tokens_in=10 tokens_out=2 usd_cents=0\n\
             total tokens_in=10 tokens_out=2 usd_cents=5\n"
        );
    }

    #[test]
    fn render_usage_reports_calls_and_the_cache_hit_share() {
        let store = Store::open_in_memory().unwrap();
        for (call_index, cached_tokens) in [(1, Some(0)), (2, Some(600)), (3, None)] {
            let (run_id, prompt_tokens) = (Some("run-1"), Some(800));
            let call = aux_store::UsageCall {
                run_id,
                agent: "main",
                provider: "deepseek",
                call_index,
                prompt_tokens,
                cached_tokens,
                ..Default::default()
            };
            store.record_usage_call(&call).unwrap();
        }
        let day = store.local_day().unwrap();
        let mut out = Vec::new();
        render_usage(&store, Some("main"), &day, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let line =
            "calls=3 turns=1 max_per_turn=3 prompt=2400 cached=600 cache_hit=37.5% completion=0";
        assert!(text.ends_with(&format!("{line}\n")), "{text}");
    }

    #[test]
    fn render_usage_says_so_when_a_day_is_empty() {
        let store = Store::open_in_memory().unwrap();
        let mut out = Vec::new();
        render_usage(&store, None, "1999-01-01", &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "usage 1999-01-01\n(no usage recorded)\n"
        );
    }
}
