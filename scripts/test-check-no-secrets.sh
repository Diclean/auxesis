#!/usr/bin/env bash
# Negative test for scripts/check-no-secrets.sh + scripts/check-personal-data.sh
# (rh-1-2). Builds a throwaway git work tree in a mktemp directory (removed on
# exit) and proves from the outside that:
#   1. tracked text containing a generic CI account name ("runner") does NOT
#      fail the scan — the CI runner account is not the owner (rh-1-2);
#   2. a planted real-shaped secret IS still caught (exit 1, "secret-looking"
#      in the output), so the scanner cannot silently rot;
#   3. a planted owner username IS caught when a real (non-generic) account
#      name is supplied, so the skip rule did not disable the check.
#
# Runs from CI (`No secrets tracked` step) and by hand.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

here="$(cd "$(dirname "$0")" && pwd -P)"
root="$(cd "$here/.." && pwd -P)"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-no-secrets-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/scripts"
cp "$root/scripts/check-no-secrets.sh" "$root/scripts/check-personal-data.sh" \
    "$root/scripts/secret-scan-allowlist.txt" "$tmp/scripts/"
# The scanners source scripts/lib/guard.sh: the fixture needs it.
cp -R "$root/scripts/lib" "$tmp/scripts/"

git -C "$tmp" init -q
git -C "$tmp" config user.name "no-secrets test"
git -C "$tmp" config user.email "no-secrets-test@auxesis.invalid"

# Run the scanner in the temp tree with a chosen account, outside any CI
# environment the test itself may inherit.
run_scan() {
    local user="$1"
    ( cd "$tmp" && env -u CI -u GITHUB_ACTIONS -u GITLAB_CI -u BUILDKITE \
        USER="$user" scripts/check-no-secrets.sh 2>&1 )
}

fail() {
    echo "FAIL: $1"
    echo "--- scanner output ---"
    printf '%s\n' "${out:-<none>}"
    exit 1
}

# 1. A CI runner account + the word "runner" in tracked text: must pass.
printf '# the hostile-auxd probe runner starts here\n' > "$tmp/probe.rs"
git -C "$tmp" add probe.rs
git -C "$tmp" commit -qm "ci-style text"

out="$(run_scan runner)" && rc=0 || rc=$?
[[ "$rc" -eq 0 ]] || fail "scan failed with USER=runner on text containing 'runner' (rc=$rc)"
[[ "$out" == *"OK: no secrets tracked"* ]] || fail "missing clean-pass line (rc=$rc)"
echo "PASS: generic account 'runner' is not scanned as personal data"

# 2. A planted real-shaped secret must still be caught, even under the generic
#    account. (Synthetic all-A value, never a real credential.)
secret="sk-$(printf 'A%.0s' {1..24})"
printf 'let leaked = "%s";\n' "$secret" > "$tmp/leak.rs"
git -C "$tmp" add leak.rs
git -C "$tmp" commit -qm "plant a secret-like value"

out="$(run_scan runner)" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || fail "planted secret-like value was NOT caught"
[[ "$out" == *"FAIL: secret-looking values in tracked files"* ]] \
    || fail "planted value failed for the wrong reason (rc=$rc)"
echo "PASS: planted secret-like value is still caught"

git -C "$tmp" rm -q leak.rs
git -C "$tmp" commit -qm "remove planted value"

# 3. A real (non-generic) owner account name must still be caught in prose.
printf 'sandbox = "/Users/probeuser/work";\n' > "$tmp/home.rs"
git -C "$tmp" add home.rs
git -C "$tmp" commit -qm "plant an owner username"

out="$(run_scan probeuser)" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || fail "planted owner username was NOT caught"
[[ "$out" == *"FAIL: the machine username appears in tracked files"* ]] \
    || fail "username hit failed for the wrong reason (rc=$rc)"
echo "PASS: planted owner username is still caught"

echo "OK: check-no-secrets self-test passed (temp tree removed)"
