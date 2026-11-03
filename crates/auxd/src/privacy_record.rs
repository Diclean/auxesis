//! AUX-EGRESS-TOOL: `privacy_record_summary`, the privacy record as counts.
//!
//! It reads the run receipts the sidebar footer counts (`GET /v1/receipts`,
//! `read_receipts`) with the footer's rule: a run left the Mac when its day
//! matches and a host it reached is not loopback. The result goes to the
//! cloud brain, so it holds counts, fixed class names, configured provider
//! ids and dates only; never a host, run id, agent, path, recipient, reason,
//! token or value from the record.
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::{Datelike, Days, NaiveDate};
use kernel_broker::{NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, Trust};
use kernel_core::privacy::PathId;
use serde_json::{json, Value};

use crate::api::receipt::{
    clean_host, read_receipts_strict, Receipt, ReceiptStatus, RECEIPT_RETENTION_DAYS,
    RECEIPT_RETENTION_ROWS,
};

pub const NAME: &str = "privacy_record_summary";

/// The protected classes the answer names.
pub const CLASSES: [&str; 8] = [
    "email", "phone", "card", "iban", "id", "health", "secret", "address",
];

/// A recorded token kind's class; every other kind (names, URLs, unknown)
/// counts as `other`, so no recorded kind string is copied out.
fn class_of(kind: &str) -> &'static str {
    match kind {
        "credit_card" => "card",
        "fr_nir" | "fr_siren" | "fr_siret" | "fr_vat" | "hu_taj" | "hu_tax_id" | "za_id"
        | "uk_nino" | "passport_mrz" | "national_id" => "id",
        _ => CLASSES
            .into_iter()
            .find(|class| *class == kind)
            .unwrap_or("other"),
    }
}

/// The footer's `PrivacyRecordCounter.isLoopback` on a receipt host (already
/// bare, IPv6 in brackets): `localhost`, `::1` and `127.0.0.0/8`.
pub fn is_loopback(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The days a call covers, both ends included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Period {
    pub label: &'static str,
    pub from: NaiveDate,
    pub to: NaiveDate,
}

/// `period` (`today` by default, `this_week` from Monday, or `since`) and
/// `since` (`YYYY-MM-DD`), read against `today`.
pub fn period(args: &Value, today: NaiveDate) -> Result<Period, &'static str> {
    const BAD: &str = "takes `period` (today, this_week or since) and `since` (YYYY-MM-DD)";
    let map = args.as_object().ok_or(BAD)?;
    if map.keys().any(|key| key != "period" && key != "since") {
        return Err(BAD);
    }
    let text = |key| match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(_) => Err(BAD),
    };
    let since = (text("since")?)
        .map(|day| NaiveDate::parse_from_str(day, "%Y-%m-%d").map_err(|_| BAD))
        .transpose()?;
    let monday = Days::new(u64::from(today.weekday().num_days_from_monday()));
    let (label, from) = match (text("period")?, since) {
        (None | Some("today"), None) => ("today", today),
        (Some("this_week"), None) => ("this_week", today - monday),
        (None | Some("since"), Some(day)) => ("since", day),
        _ => return Err(BAD),
    };
    if from > today {
        return Err("`since` is after today");
    }
    Ok(Period {
        label,
        from,
        to: today,
    })
}

/// The local day a receipt started (the footer's 10-character prefix).
fn receipt_day(receipt: &Receipt) -> Option<NaiveDate> {
    let started = receipt.started.as_deref()?.get(..10)?;
    NaiveDate::parse_from_str(started, "%Y-%m-%d").ok()
}

/// The counts of the receipts in `period`. `providers` maps a brain's host to
/// its configured provider id; any other outside host counts as `web`.
pub fn summarize(receipts: &[Receipt], period: Period, providers: &[(String, String)]) -> Value {
    let (mut left, mut stayed, mut refused, mut denied_calls, mut tokenised, mut other) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut by_provider = BTreeMap::<&str, u64>::new();
    let mut hidden: BTreeMap<&str, u64> = CLASSES.iter().map(|class| (*class, 0)).collect();
    for receipt in receipts {
        let day = receipt_day(receipt);
        if !day.is_some_and(|day| period.from <= day && day <= period.to) {
            continue;
        }
        let mut names: Vec<&str> = (receipt.hosts_contacted.iter())
            .filter(|host| !is_loopback(host))
            .map(|host| {
                let known = providers.iter().find(|(h, _)| h.eq_ignore_ascii_case(host));
                known.map_or("web", |(_, id)| id.as_str())
            })
            .collect();
        names.sort_unstable();
        names.dedup();
        if names.is_empty() {
            stayed += 1;
            let stopped = ReceiptStatus::Failed == receipt.status
                || ReceiptStatus::StoppedBudget == receipt.status;
            refused += u64::from(stopped);
        } else {
            left += 1;
        }
        names
            .into_iter()
            .for_each(|name| *by_provider.entry(name).or_default() += 1);
        let denied = receipt
            .could_not_verify
            .iter()
            .filter(|r| r.contains(" returned denied"));
        denied_calls += denied.count() as u64;
        for (kind, count) in &receipt.replaced_values {
            tokenised = tokenised.saturating_add(u64::from(*count));
            let slot = hidden.get_mut(class_of(kind)).unwrap_or(&mut other);
            *slot = slot.saturating_add(u64::from(*count));
        }
    }
    // Lists, not maps: the kernel reads `"secret": 1` as a secret's value and
    // would tokenise the count, so no class or provider name is a JSON key.
    let by_provider: Vec<Value> = (by_provider.into_iter())
        .map(|(provider, requests)| json!({"provider": provider, "requests": requests}))
        .collect();
    let hidden: Vec<Value> = (CLASSES.iter())
        .map(|class| json!({"class": class, "count": hidden[class]}))
        .collect();
    json!({
        "period": period.label,
        "from": period.from.format("%Y-%m-%d").to_string(),
        "to": period.to.format("%Y-%m-%d").to_string(),
        "requests_left_the_mac": left,
        "left_the_mac_by_provider": by_provider,
        "runs_that_stayed_on_this_mac": stayed,
        "items_hidden_by_class": hidden,
        "items_hidden_other": other,
        "items_tokenised": tokenised,
        "runs_blocked_or_refused": refused,
        "tool_calls_refused": denied_calls,
        "unit": "one request is one run receipt, the unit the sidebar counts; a run that reached two destinations counts once for each; the run asking is counted once it ends",
    })
}

/// The `(host, provider id)` pairs of the configured brains (`providers.toml`
/// and the legacy `config.toml`), hosts cut the way a receipt records them.
/// An entry with no URL (ACP) or an unreadable file names nothing.
pub fn provider_hosts(home: &Path) -> Vec<(String, String)> {
    let file = aux_providers::providers_toml::load_providers_for_home(home);
    let legacy = aux_providers::load_providers(&kernel_core::config_path(home));
    (file
        .map(|file| file.providers)
        .unwrap_or_default()
        .into_iter())
    .filter_map(|entry| Some((entry.base_url?, entry.id)))
    .chain(
        legacy
            .unwrap_or_default()
            .into_iter()
            .map(|p| (p.base_url, p.id)),
    )
    .filter(|(url, _)| url.contains("://"))
    .map(|(url, id)| (clean_host(&url), id))
    .filter(|(host, _)| !host.is_empty())
    .collect()
}

/// The read-only tool; it reads the journal on each call.
pub struct PrivacyRecordTool {
    db_path: PathBuf,
    providers: Vec<(String, String)>,
    /// The most receipts one call reads, newest first.
    cap: i64,
}

impl PrivacyRecordTool {
    pub fn new(db_path: PathBuf, providers: Vec<(String, String)>) -> Self {
        let cap = RECEIPT_RETENTION_ROWS;
        Self {
            db_path,
            providers,
            cap,
        }
    }

    /// Read at most `cap` receipts (tests).
    pub fn with_cap(mut self, cap: i64) -> Self {
        self.cap = cap;
        self
    }

    /// The answer for `args` on `today`. No store yet is said as such, never
    /// as zeros; a store that cannot be read is an error. A `since` before
    /// the retention floor starts at the oldest kept day (`kept_since`), and
    /// a read stopped by the cap inside the period gives minimums.
    pub fn answer(&self, args: &Value, today: NaiveDate) -> Result<Value, ToolError> {
        let mut period = period(args, today).map_err(|err| ToolError::invalid_args(NAME, err))?;
        let kept = today - Days::new(RECEIPT_RETENTION_DAYS.unsigned_abs());
        let clamped = period.from < kept;
        period.from = period.from.max(kept);
        let day = |date: NaiveDate| date.format("%Y-%m-%d").to_string();
        let unreadable = || ToolError::fetch("the privacy record could not be read");
        // Only NotFound is "no record yet"; any other metadata error (a
        // folder it cannot enter) is an error, never `none_yet`.
        let found = match std::fs::metadata(&self.db_path) {
            Ok(_) => true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(unreadable()),
        };
        if !found {
            return Ok(json!({
                "period": period.label,
                "from": day(period.from),
                "to": day(period.to),
                "record": "none_yet",
                "note": "There is no privacy record on this Mac yet.",
            }));
        }
        // Strict: a store that vanished since the check fails the read; zeros
        // only come from a store that was read.
        let receipts =
            read_receipts_strict(&self.db_path, None, self.cap).map_err(|_| unreadable())?;
        let mut answer = summarize(&receipts, period, &self.providers);
        // Newest first: when the cap stopped the read, the oldest row read
        // must be older than the period, or older runs may be missing.
        let oldest = receipts.last().and_then(receipt_day);
        let complete =
            (receipts.len() as i64) < self.cap || oldest.is_some_and(|d| d < period.from);
        answer["complete"] = json!(complete);
        if !complete {
            answer["counts_are_minimums"] = json!(true);
        }
        if clamped {
            answer["kept_since"] = json!(day(kept));
        }
        Ok(answer)
    }
}

impl NativeTool for PrivacyRecordTool {
    fn native_name(&self) -> &'static str {
        NAME
    }

    fn native_description(&self) -> &'static str {
        "Count what the privacy record shows for a period (default today): requests that left the Mac per brain, items hidden per class, items tokenised, runs and tool calls refused. Counts only, from the record the sidebar counts."
    }

    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
            json!({"type": "object", "additionalProperties": false, "properties": {
                "period": {"type": "string", "enum": ["today", "this_week", "since"]},
                "since": {"type": "string", "description": "First day (YYYY-MM-DD) for period since"}
            }})
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for PrivacyRecordTool {
    /// A read of the owner's own local store, mounted in both modes like
    /// `owner_profile`; the session gate still sees the result.
    fn path_id(&self) -> PathId {
        PathId::B23
    }

    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let answer = self.answer(args, chrono::Local::now().date_naive())?;
        Ok(ToolOutput::ok(answer.to_string()))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            output_trust: Trust::Trusted,
            ..ToolClass::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(text: &str) -> NaiveDate {
        NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
    }

    /// A store holding one outside run on each of `days`, oldest first.
    fn store_with(days: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = aux_store::Store::open(&db).unwrap();
        for (n, started) in days.iter().enumerate() {
            let mut receipt = crate::api::receipt::build_receipt(&[]);
            receipt.run_id = format!("turn-{n}");
            receipt.started = Some(format!("{started} 09:00:00"));
            receipt.hosts_contacted = vec!["api.deepseek.com".into()];
            let payload = serde_json::to_string(&receipt).unwrap();
            store
                .log_run_finished_once(&receipt.run_id, &payload)
                .unwrap();
        }
        (dir, db)
    }

    #[test]
    fn a_missing_store_says_there_is_no_record_yet_and_gives_no_count() {
        let dir = tempfile::tempdir().unwrap();
        let tool = PrivacyRecordTool::new(dir.path().join("none.db"), Vec::new());
        let answer = tool.answer(&json!({}), day("2026-10-29")).unwrap();
        assert_eq!(answer["record"], "none_yet", "{answer}");
        assert!(answer.get("requests_left_the_mac").is_none(), "{answer}");
        assert!(answer.get("items_tokenised").is_none(), "{answer}");
    }

    #[test]
    fn a_store_under_an_unreadable_folder_is_an_error_not_none_yet() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, db) = store_with(&["2026-10-29"]);
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let hidden = locked.join("store.db");
        std::fs::rename(&db, &hidden).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::metadata(&hidden).is_ok();
        let answer =
            PrivacyRecordTool::new(hidden, Vec::new()).answer(&json!({}), day("2026-10-29"));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        if readable {
            return; // root reads through 000: nothing to prove here.
        }
        assert!(answer.is_err(), "{answer:?}");
    }

    #[test]
    fn a_store_that_vanished_before_the_read_is_an_error_not_zeros() {
        // The tool's read never maps a missing file to an empty list: once
        // the existence check has passed, a vanished store fails the read.
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("store.db");
        assert!(crate::api::receipt::read_receipts_strict(&gone, None, 10).is_err());
    }

    #[test]
    fn a_receipt_row_that_does_not_decode_is_an_error_never_zeros() {
        let (_dir, db) = store_with(&[]);
        let store = aux_store::Store::open(&db).unwrap();
        store
            .log_run_finished_once("turn-bad", r#"{"run_id":"turn-bad","agent":7}"#)
            .unwrap();
        let tool = PrivacyRecordTool::new(db.clone(), Vec::new());
        assert!(tool.answer(&json!({}), day("2026-10-29")).is_err());
        // The sidebar's reader keeps skipping such a row.
        assert!(crate::api::receipt::read_receipts(&db, None, 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn an_unreadable_store_is_an_error_never_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        std::fs::write(&db, b"\xff\x00 not a database \x13\x37".repeat(64)).unwrap();
        let tool = PrivacyRecordTool::new(db, Vec::new());
        assert!(tool.answer(&json!({}), day("2026-10-29")).is_err());
    }

    #[test]
    fn the_counts_stop_at_the_cap_only_as_minimums() {
        // Five runs in the week, a cap of four: the oldest run read is still
        // in the week, so more may exist; the counts are minimums.
        let days = [
            "2026-10-26",
            "2026-10-27",
            "2026-10-27",
            "2026-10-28",
            "2026-10-29",
        ];
        let (_dir, db) = store_with(&days);
        let tool = PrivacyRecordTool::new(db, Vec::new()).with_cap(4);
        let week = tool
            .answer(&json!({"period": "this_week"}), day("2026-10-29"))
            .unwrap();
        assert_eq!(week["complete"], false, "{week}");
        assert_eq!(week["counts_are_minimums"], true);
        assert_eq!(week["requests_left_the_mac"], 4);
        // Today ends after the oldest run read: nothing older can belong to it.
        let today = tool.answer(&json!({}), day("2026-10-29")).unwrap();
        assert_eq!(today["complete"], true, "{today}");
        assert_eq!(today["requests_left_the_mac"], 1);
        assert!(today.get("counts_are_minimums").is_none());
    }

    #[test]
    fn a_since_before_retention_starts_at_the_oldest_kept_day() {
        let (_dir, db) = store_with(&["2026-07-31", "2026-10-29"]);
        let tool = PrivacyRecordTool::new(db, Vec::new());
        let answer = tool
            .answer(&json!({"since": "2026-01-01"}), day("2026-10-29"))
            .unwrap();
        assert_eq!(answer["from"], "2026-07-31", "90 days kept: {answer}");
        assert_eq!(answer["kept_since"], "2026-07-31");
        assert_eq!(answer["requests_left_the_mac"], 2);
        let inside = tool
            .answer(&json!({"since": "2026-10-01"}), day("2026-10-29"))
            .unwrap();
        assert!(inside.get("kept_since").is_none(), "{inside}");
    }

    #[test]
    fn the_count_is_not_the_sidebar_list_limit() {
        // The app lists 100 receipts; the footer's rule has no cap, and
        // neither does the count: 101 runs today are 101.
        let (_dir, db) = store_with(&["2026-10-29"; 101]);
        let tool = PrivacyRecordTool::new(db, Vec::new());
        let answer = tool.answer(&json!({}), day("2026-10-29")).unwrap();
        assert_eq!(answer["requests_left_the_mac"], 101);
        assert_eq!(answer["complete"], true);
    }

    #[test]
    fn an_empty_store_gives_zeros() {
        let (_dir, db) = store_with(&[]);
        let tool = PrivacyRecordTool::new(db, Vec::new());
        let answer = tool.answer(&json!({}), day("2026-10-29")).unwrap();
        assert!(answer.get("record").is_none(), "{answer}");
        for key in [
            "requests_left_the_mac",
            "items_tokenised",
            "runs_blocked_or_refused",
        ] {
            assert_eq!(answer[key], 0, "{key}");
        }
        assert_eq!(answer["left_the_mac_by_provider"], json!([]));
        let hidden = answer["items_hidden_by_class"].as_array().unwrap();
        assert_eq!(hidden.len(), CLASSES.len());
        assert!(hidden.iter().all(|row| row["count"] == 0), "{answer}");
    }

    #[test]
    fn the_period_filter_picks_today_the_week_or_a_start_day() {
        let thursday = day("2026-10-29");
        for bad in [
            json!({"period": "since"}),
            json!({"since": "2026-11-01"}),
            json!({"period": "year"}),
            json!({"since": "29/10/2026"}),
            json!({"other": 1}),
        ] {
            assert!(period(&bad, thursday).is_err(), "{bad}");
        }
        let receipt = |started: &str, host: &str| {
            let mut receipt = crate::api::receipt::build_receipt(&[]);
            receipt.started = Some(format!("{started} 09:00:00"));
            receipt.hosts_contacted = vec![host.to_string()];
            receipt
        };
        let receipts = [
            receipt("2026-10-29", "api.deepseek.com"),
            receipt("2026-10-27", "api.deepseek.com"),
            receipt("2026-10-20", "example.test"),
            receipt("2026-10-29", "127.0.0.1"),
            receipt("2026-10-29", "[::1]"),
        ];
        let providers = [("api.deepseek.com".to_string(), "deepseek".to_string())];
        let count = |args: Value| {
            let period = period(&args, thursday).unwrap();
            let answer = summarize(&receipts, period, &providers);
            let rows = answer["left_the_mac_by_provider"].to_string();
            (
                period.from,
                answer["requests_left_the_mac"].as_u64().unwrap(),
                rows,
            )
        };
        let deepseek = |n: u64| format!(r#"{{"provider":"deepseek","requests":{n}}}"#);
        let today = count(json!({}));
        assert_eq!(today, (thursday, 1, format!("[{}]", deepseek(1))));
        let week = count(json!({"period": "this_week"}));
        assert_eq!(week, (day("2026-10-26"), 2, format!("[{}]", deepseek(2))));
        let since = count(json!({"since": "2026-10-01"}));
        let web = r#"{"provider":"web","requests":1}"#;
        assert_eq!(
            since,
            (day("2026-10-01"), 3, format!("[{},{web}]", deepseek(2)))
        );
    }
}
