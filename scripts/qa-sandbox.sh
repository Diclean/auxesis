#!/usr/bin/env bash
# Boots Auxesis in a throwaway sandbox: fresh HOME/AUXESIS_HOME, no real keys.
# Used by builders and breakers alike. Never touches your real ~/.auxesis.
#
# The guard is armed (AUXESIS_SANDBOX=1) and both HOME and AUXESIS_HOME
# are literal mktemp paths; auxd binds an explicit ephemeral port
# (AUXESIS_API_PORT=0) and doctor probes the port auxd actually announced.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REAL_HOME="$(guard_real_home)"
if [ -n "${TMPDIR:-}" ] && { guard_under "$TMPDIR" "$REAL_HOME" || guard_under "$TMPDIR" "$REAL_HOME/.auxesis"; }; then
    echo "qa-sandbox: refusing: TMPDIR=$TMPDIR resolves into the real home ($REAL_HOME)" >&2
    exit 1
fi
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-qa.XXXXXX")"
export HOME="$SANDBOX"
export AUXESIS_HOME="$SANDBOX/home"
export AUXESIS_SANDBOX=1
export AUXESIS_API_PORT=0

cleanup() {
    if [[ -n "${AUXD_PID:-}" ]]; then
        kill "$AUXD_PID" 2>/dev/null || true
        wait "$AUXD_PID" 2>/dev/null || true
    fi
    rm -rf "$SANDBOX"
}
trap cleanup EXIT

echo "qa-sandbox: sandbox at $SANDBOX"

cargo build --quiet -p aux-cli -p auxd

"$ROOT/target/debug/auxd" >"$SANDBOX/auxd.log" 2>&1 &
AUXD_PID=$!

PORT=""
for _ in $(seq 1 50); do
    PORT="$(sed -n 's/.*auxd api on http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$SANDBOX/auxd.log" | head -1)"
    if [[ -n "$PORT" ]]; then
        break
    fi
    if ! kill -0 "$AUXD_PID" 2>/dev/null; then
        echo "FAIL: auxd exited before announcing its API port. Log:" >&2
        cat "$SANDBOX/auxd.log" >&2
        exit 1
    fi
    sleep 0.1
done

if [[ -z "$PORT" ]]; then
    echo "FAIL: auxd did not announce its API port. Log:" >&2
    cat "$SANDBOX/auxd.log" >&2
    exit 1
fi

# The explicit loopback port is the sanctioned sandbox client form (the guard
# refuses AUXESIS_API and the default 2893).
AUXESIS_API_PORT="$PORT" "$ROOT/target/debug/aux" doctor

echo "qa-sandbox: auxd started OK on port $PORT"
