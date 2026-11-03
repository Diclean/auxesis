//! End-to-end tests of the budget & kill-switch CLI surface:
//! `aux stop`, `aux resume`, `aux usage`, and the budget denial path of
//! `aux chat` (`[budgets]` in config.toml + the recorded usage meter).
//!
//! Everything runs in a throwaway Auxesis home with the fake provider: no
//! network, no keys.

use kernel_core::UsageKind;
use tempfile::tempdir;

mod common;
use common::sandbox_command;

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

const FAKE_PROVIDER: &str = r#"
[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"
"#;

fn write_config(home: &std::path::Path, extra: &str) {
    std::fs::create_dir_all(home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        format!("version = 1\nprivacy.mode = \"open\"\nlog_level = \"info\"\ndefault_agent = \"main\"\n{extra}"),
    )
    .unwrap();
}

#[test]
fn stop_and_resume_toggle_the_marker_round_trip() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["stop"])
        .output()
        .expect("run aux stop");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stop failed:\n{stdout}");
    assert!(stdout.contains("kill switch engaged"), "stdout:\n{stdout}");
    assert!(home.join("STOP").is_file(), "marker must exist");

    // Idempotent: stopping again succeeds and leaves the marker in place.
    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["stop"])
        .output()
        .expect("run aux stop again");
    assert!(output.status.success());
    assert!(home.join("STOP").is_file());

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["resume"])
        .output()
        .expect("run aux resume");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "resume failed:\n{stdout}");
    assert!(stdout.contains("kill switch released"), "stdout:\n{stdout}");
    assert!(!home.join("STOP").exists(), "marker must be gone");

    // Resuming again is a no-op, not an error.
    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["resume"])
        .output()
        .expect("run aux resume again");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("was not engaged"), "stdout:\n{stdout}");
}

#[test]
fn usage_prints_the_recorded_day() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    {
        let store = aux_store::Store::open(&home.join("store.db")).unwrap();
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
                4,
                "tokens",
                "2026-10-03 08:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "axis",
                UsageKind::UsdCents,
                3,
                "cents",
                "2026-10-03 09:00:00",
            )
            .unwrap();
    }

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["usage", "--day", "2026-10-03"])
        .output()
        .expect("run aux usage");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "usage failed:\n{stdout}");
    assert!(stdout.contains("usage 2026-10-03"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("main tokens_in=10 tokens_out=4 usd_cents=0"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("axis tokens_in=0 tokens_out=0 usd_cents=3"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("total tokens_in=10 tokens_out=4 usd_cents=3"),
        "stdout:\n{stdout}"
    );

    // Restricting to one agent hides the others.
    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["usage", "--day", "2026-10-03", "--agent", "main"])
        .output()
        .expect("run aux usage --agent");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("main tokens_in=10"), "stdout:\n{stdout}");
    assert!(!stdout.contains("axis"), "stdout:\n{stdout}");

    // An untouched day reports that plainly.
    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["usage", "--day", "1999-01-01"])
        .output()
        .expect("run aux usage on an empty day");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("(no usage recorded)"), "stdout:\n{stdout}");
}

#[test]
fn usage_rejects_a_malformed_day() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["usage", "--day", "03/10/2026"])
        .output()
        .expect("run aux usage");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("expected YYYY-MM-DD"), "stderr:\n{stderr}");
}

#[test]
fn usage_rejects_an_impossible_calendar_date() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["usage", "--day", "2026-02-30"])
        .output()
        .expect("run aux usage");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("no such calendar date"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn chat_usage_is_recorded_and_over_budget_calls_are_denied() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    // A cap the first call comfortably fits under: admission now includes the
    // caller's own reserve (B-01R), so a tiny cap no longer admits the call
    // and then overshoots. The cap is pinned to the recorded usage *after*
    // the first call, which is what must block the next one.
    write_config(
        &home,
        &format!("[budgets.default]\ntokens_in = 1000000\n{FAKE_PROVIDER}"),
    );

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "--agent", "main", "hello"])
        .output()
        .expect("run aux chat");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "first chat failed:\n{stdout}");
    assert!(stdout.contains("[fake:fakey] hello"), "stdout:\n{stdout}");

    // The provider call left usage rows behind for today.
    let store = aux_store::Store::open(&home.join("store.db")).unwrap();
    let day = store.local_day().unwrap();
    let totals = store.usage_totals("main", &day).unwrap();
    assert!(totals.tokens_in >= 1, "usage missing: {totals:?}");
    assert!(totals.tokens_out >= 1, "usage missing: {totals:?}");

    // The cap now equals what was recorded: any further call would have to
    // reserve input tokens that no longer fit, so it is denied before the
    // provider is called, and the denial is audited.
    write_config(
        &home,
        &format!(
            "[budgets.default]\ntokens_in = {}\n{FAKE_PROVIDER}",
            totals.tokens_in
        ),
    );
    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "--agent", "main", "again"])
        .output()
        .expect("run aux chat under cap");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "over-budget chat must fail");
    assert!(stderr.contains("budget denied"), "stderr:\n{stderr}");
    assert!(stderr.contains("tokens_in"), "stderr:\n{stderr}");
    assert_eq!(store.event_count("budget.denied").unwrap(), 1);
}

#[test]
fn chat_still_works_without_any_budget_section() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    write_config(&home, FAKE_PROVIDER);

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "--agent", "main", "hello"])
        .output()
        .expect("run aux chat");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "chat failed:\n{stdout}");
    assert!(stdout.contains("[fake:fakey] hello"), "stdout:\n{stdout}");
}
