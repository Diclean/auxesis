#!/usr/bin/env bash
# Summarise one nightly hero leg for $GITHUB_STEP_SUMMARY (phase1.md §6).
#
#   scripts/nightly-summary.sh <leg> <report-file> <brains.toml>
#
# Prints a markdown table of the leg's passed and skipped tests, with the
# reason for each skip. Exit 1 when the leg is `required` and a test was
# skipped, no test passed, or the number of passed tests differs from the
# leg's `expected`; exit 0 otherwise. Exit 2 when the leg's `required` field
# is not exactly `true` or `false`, or a required leg has no `expected`. A leg
# whose key env var is empty prints `skipped: <leg>: no key` and exits 0
# unless it is required.
#
# The report holds one `passed <test> <brain>` or `skipped <test> <brain>
# <reason>` line per test (qa/acceptance/hero_send_invite.rs, `record`).
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <leg> <report-file> <brains.toml>" >&2
  exit 2
fi
leg="$1"
report="$2"
toml="$3"

if ! grep -qx "\[$leg\]" "$toml"; then
  echo "nightly-summary: unknown leg: $leg" >&2
  exit 2
fi

# Prints one `field = value` from the [leg] table, without quotes or comments.
toml_value() {
  awk -v table="[$leg]" -v field="$1" '
    /^\[/ { in_leg = ($0 == table); next }
    in_leg && $1 == field && $2 == "=" {
      value = $0
      sub(/^[^=]*=[ \t]*/, "", value)
      sub(/[ \t]*#.*$/, "", value)
      gsub(/"/, "", value)
      print value
      exit
    }
  ' "$toml"
}

required="$(toml_value required)"
if [[ "$required" != true && "$required" != false ]]; then
  echo "nightly-summary: $leg: required must be true or false" >&2
  exit 2
fi

expected="$(toml_value expected)"
if [[ "$required" == true && -z "$expected" ]]; then
  echo "nightly-summary: $leg is required and has no expected" >&2
  exit 2
fi

key="$(toml_value key)"

if [[ -n "$key" && -z "${!key:-}" ]]; then
  echo "skipped: $leg: no key"
  if [[ "$required" == true ]]; then
    echo "nightly-summary: $leg is required and has no key" >&2
    exit 1
  fi
  exit 0
fi

if [[ ! -f "$report" ]]; then
  if [[ "$required" == true ]]; then
    echo "nightly-summary: $leg is required and has no report at $report" >&2
    exit 1
  fi
  echo "skipped: $leg: no report"
  exit 0
fi

ran="$(grep -c '^passed ' "$report" || true)"
skipped="$(grep -c '^skipped ' "$report" || true)"

echo "### Nightly brain: $leg"
echo
echo "| leg | ran | skipped | required |"
echo "|---|---:|---:|---|"
echo "| $leg | $ran | $skipped | $required |"
if [[ "$skipped" -gt 0 ]]; then
  echo
  echo "Skipped:"
  awk '$1 == "skipped" {
    line = $0
    sub(/^skipped [^ ]+ [^ ]+ /, "", line)
    printf "- `%s` (%s): %s\n", $2, $3, line
  }' "$report"
fi

if [[ "$required" == true && ( "$skipped" -gt 0 || "$ran" -eq 0 || "$ran" -ne "$expected" ) ]]; then
  echo "nightly-summary: $leg is required: $ran ran, $skipped skipped, expected $expected" >&2
  exit 1
fi
exit 0
