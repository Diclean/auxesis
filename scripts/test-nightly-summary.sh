#!/usr/bin/env bash
# Tests for scripts/nightly-summary.sh (phase1.md §6). Writes its fixtures to a
# mktemp directory (removed on exit) and runs the summary in a clean env, so a
# secret in the caller's env cannot change a case. Bash and standard tools only.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd -P)"
root="$(cd "$here/.." && pwd -P)"
summary="$here/nightly-summary.sh"
toml="$root/qa/acceptance/brains.toml"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-nightly-summary-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

# run_summary_toml <leg> <report> <toml> [VAR=value ...]: sets $rc and $out.
run_summary_toml() {
  local leg="$1" report="$2" table="$3"
  shift 3
  set +e
  out="$(env -i PATH="$PATH" "$@" "$summary" "$leg" "$report" "$table" 2>&1)"
  rc=$?
  set -e
}

# run_summary <leg> <report> [VAR=value ...]: runs against brains.toml.
run_summary() {
  local leg="$1" report="$2"
  shift 2
  run_summary_toml "$leg" "$report" "$toml" "$@"
}

# check <name> <want: 0|nonzero> <text the output must contain, or empty>
check() {
  local name="$1" want="$2" text="$3"
  if [[ "$want" == 0 ]]; then
    [[ "$rc" -eq 0 ]] || { bad "$name: exit $rc, want 0"; return; }
  else
    [[ "$rc" -ne 0 ]] || { bad "$name: exit 0, want non-zero"; return; }
  fi
  if [[ -n "$text" && "$out" != *"$text"* ]]; then
    bad "$name: output lacks '$text'"
    return
  fi
  ok "$name"
}

# check_code <name> <want-exit> <text the output must contain, or empty>
check_code() {
  local name="$1" want="$2" text="$3"
  if [[ "$rc" -ne "$want" ]]; then
    bad "$name: exit $rc, want $want"
    return
  fi
  if [[ -n "$text" && "$out" != *"$text"* ]]; then
    bad "$name: output lacks '$text'"
    return
  fi
  ok "$name"
}

all_six="$tmp/fake-all-passed.report"
cat >"$all_six" <<'REPORT'
passed hero_forced_invite_runs_at_most_once_per_turn fake
passed hero_private_send_invite fake
passed hero_dropped_call_is_refused_then_retried fake
passed hero_open_invite_is_approved_and_sent fake
passed hero_open_unanswered_approval_sends_nothing fake
passed hero_open_plain_gmail_send_is_refused fake
REPORT

fake_skip="$tmp/fake-with-skip.report"
cat >"$fake_skip" <<'REPORT'
passed hero_private_send_invite fake
skipped hero_open_invite_is_approved_and_sent fake set AUX_HERO_CLOUD_URL, AUX_HERO_CLOUD_KEY and AUX_HERO_CLOUD_MODEL
REPORT

only_skips="$tmp/fake-only-skips.report"
cat >"$only_skips" <<'REPORT'
skipped hero_private_send_invite fake set AUX_HERO_CLOUD_URL, AUX_HERO_CLOUD_KEY and AUX_HERO_CLOUD_MODEL
skipped hero_open_invite_is_approved_and_sent fake set AUX_HERO_CLOUD_URL, AUX_HERO_CLOUD_KEY and AUX_HERO_CLOUD_MODEL
REPORT

cloud_skips="$tmp/cloud-with-skips.report"
cat >"$cloud_skips" <<'REPORT'
passed hero_private_send_invite cloud
skipped hero_dropped_call_is_refused_then_retried cloud only the scripted brain drops a call
skipped hero_open_plain_gmail_send_is_refused cloud set AUX_HERO_CLOUD_URL, AUX_HERO_CLOUD_KEY and AUX_HERO_CLOUD_MODEL
REPORT

short_report="$tmp/needs-two-short.report"
cat >"$short_report" <<'REPORT'
passed hero_private_send_invite fake
REPORT

exact_report="$tmp/needs-two-exact.report"
cat >"$exact_report" <<'REPORT'
passed hero_private_send_invite fake
passed hero_open_invite_is_approved_and_sent fake
REPORT

empty_report="$tmp/empty.report"
: >"$empty_report"

missing_report="$tmp/never-written.report"

# A fixture table for legs brains.toml must not hold: a required leg with a
# key, a leg with no `required`, a required leg with no `expected`, and a
# required leg whose expected count is two.
fixture_toml="$tmp/fixture-brains.toml"
cat >"$fixture_toml" <<'TOML'
[needs-key]
required = true
key = "AUX_NIGHTLY_SUMMARY_TEST_KEY"
expected = 1

[no-required]
key = "AUX_NIGHTLY_SUMMARY_TEST_KEY"

[no-expected]
required = true

[needs-two]
required = true
expected = 2
TOML

# 1. Required leg, every test passed: exit 0, table row shows six ran.
run_summary fake "$all_six"
check "required leg, all passed" 0 "| fake | 6 | 0 | true |"

# 2. Required leg with a skip: exit non-zero, the skip is listed with its reason.
run_summary fake "$fake_skip"
check "required leg with a skip" nonzero "- \`hero_open_invite_is_approved_and_sent\` (fake): set AUX_HERO_CLOUD_URL"

# 3. Optional leg with skips: exit 0, every skip listed, key never printed.
run_summary cloud "$cloud_skips" AUXESIS_CLOUD_KEY=not-a-real-key
check "optional leg with skips" 0 "- \`hero_dropped_call_is_refused_then_retried\` (cloud): only the scripted brain drops a call"
if [[ "$out" == *not-a-real-key* ]]; then
  bad "optional leg with skips: the key was printed"
else
  ok "optional leg with skips: the key is not printed"
fi

# 4. Required leg, report missing: exit non-zero.
run_summary fake "$missing_report"
check "required leg, report missing" nonzero "no report"

# 5. Optional leg, key absent: exit 0 with the no-key line, nothing run.
run_summary cloud "$missing_report"
check "optional leg, no key" 0 "skipped: cloud: no key"

# 6. Required leg, report present but no test passed: exit non-zero.
run_summary fake "$empty_report"
check "required leg, no test passed" nonzero "| fake | 0 | 0 | true |"

# 7. A leg that is not in brains.toml is a usage error.
run_summary local "$all_six"
check "unknown leg" nonzero "unknown leg: local"

# 8. Required leg whose key env var is absent: exit 1, nothing run.
run_summary_toml needs-key "$all_six" "$fixture_toml"
check_code "required leg, no key" 1 "skipped: needs-key: no key"

# 9. Required leg with only skips: exit 1, the skip is listed with its reason.
run_summary fake "$only_skips"
check_code "required leg, only skips" 1 "- \`hero_private_send_invite\` (fake): set AUX_HERO_CLOUD_URL"

# 10. A leg with no `required` field is a configuration error.
run_summary_toml no-required "$all_six" "$fixture_toml"
check_code "missing required field" 2 "required must be true or false"

# 11. A required leg with no `expected` is a configuration error.
run_summary_toml no-expected "$all_six" "$fixture_toml"
check_code "required leg, no expected" 2 "is required and has no expected"

# 12. Required leg, fewer passes than expected: exit 1.
run_summary_toml needs-two "$short_report" "$fixture_toml"
check_code "required leg, ran below expected" 1 "expected 2"

# 13. Required leg, as many passes as expected: exit 0.
run_summary_toml needs-two "$exact_report" "$fixture_toml"
check_code "required leg, ran equals expected" 0 "| needs-two | 2 | 0 | true |"

echo "test-nightly-summary: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
