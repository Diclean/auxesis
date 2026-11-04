#!/usr/bin/env bash
# Fail if a secret-looking file or value is tracked by git.
# Runs in CI and from the versioned pre-commit hook (.githooks/pre-commit,
# installed with scripts/install-hooks.sh).
#
# Scope: the WHOLE tracked tree (not just crates/scripts as before). Known
# synthetic fixtures are allowlisted, each with a justification, in
# scripts/secret-scan-allowlist.txt.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # Refuse a contradictory sandbox HOME

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd "$here/.." && pwd -P)"

# Optional path argument: scan that directory instead of this repository's
# tracked tree. Without an argument the tracked tree is scanned, as before.
target="${1:-}"
if [[ -n "$target" ]]; then
    if [[ ! -d "$target" ]]; then
        echo "FAIL: not a directory: $target" >&2
        exit 2
    fi
    cd "$target"
    scope="the scanned tree"
    env_msg="a .env file is in the scanned tree:"
    # 1. .env files must never be there (only .env.example is allowed).
    rc=0
    tracked_env="$(find . -type f \( -name '.env' -o -name '.env.*' \) ! -name '.env.example' -print | sed -e 's|^\./||' | sort)" || rc=$?
    if (( rc != 0 )); then
        echo "FAIL: the .env scan itself failed (exit $rc) — refusing to report a clean scan" >&2
        exit 2
    fi
else
    # A scan that can see no git tree proves nothing: fail loudly instead of
    # printing the clean-pass line.
    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "FAIL: not inside a git work tree — refusing to report a clean scan" >&2
        exit 1
    fi
    cd "$(git rev-parse --show-toplevel)"
    scope="tracked files"
    env_msg="a .env file is tracked by git:"
    # 1. .env files must never be tracked (only .env.example is allowed).
    tracked_env="$(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -v '\.env\.example$' || true)"
fi

allowlist="$root/scripts/secret-scan-allowlist.txt"
fail=0

if [[ -n "$tracked_env" ]]; then
    echo "FAIL: $env_msg"
    echo "$tracked_env"
    fail=1
fi

# 2. Secret-looking values must not appear anywhere in the tracked tree.
#    Patterns: our own AUX_KEY_* names, vendor key prefixes (including the
#    sk-live-/sk-proj- shapes), AWS access key IDs, Slack tokens, private-key
#    PEM headers, Bearer JWTs. Lengths are tuned so ordinary fixture text does
#    not trip the scan; anything that still trips it is either a real secret
#    or must be justified in the allowlist.
pattern='AUX_KEY_[A-Z0-9_]+=[A-Za-z0-9_./+\-]{20,}|sk-[A-Za-z0-9]{20,}|sk-(live|proj|ant|test|canary|fake|symlink)-[A-Za-z0-9_-]{16,}|liquid_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[abp]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer eyJ[A-Za-z0-9_-]{10,}'

# Scratch files live in mktemp paths (never the old fixed /tmp/... path) and
# are removed on every exit path.
scratch="$(mktemp "${TMPDIR:-/tmp}/auxesis-secret-scan.XXXXXX")"
filtered="$(mktemp "${TMPDIR:-/tmp}/auxesis-secret-scan-filtered.XXXXXX")"
trap 'rm -f "$scratch" "$filtered"' EXIT

rc=0
if [[ -n "$target" ]]; then
    grep -r -n -I -E "$pattern" --exclude-dir=.git --exclude='secret-scan-allowlist.txt' . \
        | sed -e 's|^\./||' >"$scratch" || rc=$?
else
    git grep -n -I -E "$pattern" -- . ':(exclude)scripts/secret-scan-allowlist.txt' \
        >"$scratch" 2>/dev/null || rc=$?
fi

if [[ "$rc" -gt 1 ]]; then
    echo "FAIL: the secret scan itself failed (exit $rc) — refusing to report a clean scan" >&2
    exit 2
fi

if [[ "$rc" -eq 0 ]]; then
    if [[ -f "$allowlist" ]]; then
        # Allowlist entries are EREs matched against `path:line:content`.
        grep -v -E -f <(sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$allowlist") \
            "$scratch" >"$filtered" || true
    else
        cp "$scratch" "$filtered"
    fi
    if [[ -s "$filtered" ]]; then
        cat "$filtered"
        echo "FAIL: secret-looking values in $scope (above)"
        echo "      if a hit is a synthetic fixture, justify it in scripts/secret-scan-allowlist.txt"
        fail=1
    fi
fi

# 3. Personal data (owner username + machine temp paths) — separate control,
#    same whole-tree scope.
if [[ -n "$target" ]]; then
    if ! "$root/scripts/check-personal-data.sh" "$target"; then
        fail=1
    fi
else
    if ! "$root/scripts/check-personal-data.sh"; then
        fail=1
    fi
fi

if [[ "$fail" -eq 0 ]]; then
    echo "OK: no secrets tracked"
fi
exit "$fail"
