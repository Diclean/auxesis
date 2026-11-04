#!/usr/bin/env bash
# Build and run the Auxesis Mac app against a disposable sandbox daemon.
#
#   scripts/run-auxesis-mac.sh          # build, start auxd in a temp home, run the app
#   scripts/run-auxesis-mac.sh --shot   # run briefly and screencapture the window
#
# Safety: auxd and the app only ever see an explicit sandbox environment
# (`HOME`/`AUXESIS_HOME` under a fresh `mktemp -d`, `AUXESIS_SANDBOX=1`,
# `AUXESIS_API_PORT=0`); they never inherit the caller's HOME. A `TMPDIR`,
# `HOME` or `AUXESIS_HOME` that resolves into the real home is refused. auxd binds 127.0.0.1 on an ephemeral port (AUXESIS_API_PORT=0)
# and the script reads the actual port back from its log.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$APP_DIR/../.." && pwd)"

# Shared guard + explicit real-home refusal. `TMPDIR` pointing
# at the real home would make `mktemp -d` create the sandbox inside it.
# shellcheck source=../../../scripts/lib/guard.sh
source "$REPO_ROOT/scripts/lib/guard.sh"

REAL_HOME="$(guard_real_home)"
refuse_real_input() {
  local label="$1" value="${2:-}"
  [ -n "$value" ] || return 0
  if guard_under "$value" "$REAL_HOME" || guard_under "$value" "$REAL_HOME/.auxesis"; then
    echo "run-auxesis-mac: refusing: $label=$value resolves into the real home ($REAL_HOME)" >&2
    exit 1
  fi
}
refuse_real_input "AUXESIS_HOME" "${AUXESIS_HOME:-}"
refuse_real_input "TMPDIR" "${TMPDIR:-}"
# A HOME *inside* the real home is contradictory.
if [ -n "${HOME:-}" ] && guard_under "$HOME" "$REAL_HOME/.auxesis"; then
  echo "run-auxesis-mac: refusing: HOME=$HOME resolves into the real home ($REAL_HOME)" >&2
  exit 1
fi
# Explicit sandbox use (AUXESIS_HOME set) must run with a temp HOME: a HOME
# resolving to REAL_HOME would leak the caller's HOME/caches into the build.
if [ -n "${AUXESIS_HOME:-}" ] && [ -n "${HOME:-}" ] && guard_under "$HOME" "$REAL_HOME"; then
  echo "run-auxesis-mac: refusing: AUXESIS_HOME is set but HOME=$HOME resolves to the real home ($REAL_HOME) — run with a literal mktemp HOME" >&2
  exit 1
fi

AUXD="${AUXESIS_MAC_AUXD:-}"
for candidate in "$REPO_ROOT/target/release/auxd" "$REPO_ROOT/target/debug/auxd"; do
  if [ -n "$AUXD" ]; then
    break
  fi
  if [ -x "$candidate" ]; then
    AUXD="$candidate"
    break
  fi
done
if [ -z "$AUXD" ] || [ ! -x "$AUXD" ]; then
  echo "run-auxesis-mac: no prebuilt auxd at target/{release,debug}/auxd" >&2
  echo "build it first: cargo build -p auxd --release" >&2
  echo "or point AUXESIS_MAC_AUXD at an existing binary" >&2
  exit 1
fi

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-mac.XXXXXX")"
HOME_SANDBOX="$SANDBOX/home"
mkdir -p "$HOME_SANDBOX"
case "$HOME_SANDBOX" in
  "$SANDBOX"/*) ;;
  *) echo "run-auxesis-mac: refusing to run: sandbox escaped $SANDBOX" >&2; exit 1 ;;
esac
# A symlinked TMPDIR could still have produced a sandbox inside the real
# home: verify the created paths before anything runs.
if guard_under "$SANDBOX" "$REAL_HOME" || guard_under "$SANDBOX" "$REAL_HOME/.auxesis"; then
  echo "run-auxesis-mac: refusing: sandbox $SANDBOX resolves into the real home ($REAL_HOME)" >&2
  exit 1
fi

AUXD_PID=""
APP_PID=""
cleanup() {
  if [ -n "$APP_PID" ]; then
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
  fi
  if [ -n "$AUXD_PID" ]; then
    kill "$AUXD_PID" 2>/dev/null || true
    wait "$AUXD_PID" 2>/dev/null || true
  fi
  if [ "${AUXESIS_MAC_KEEP_SANDBOX:-0}" = "1" ]; then
    echo "sandbox kept: $SANDBOX"
  else
    rm -rf "$SANDBOX"
  fi
}
trap cleanup EXIT INT TERM

# Build and children never inherit the caller's HOME/caches: a temp build
# home plus explicit cache dirs keep ~/Library, ~/.cache and ~/.swiftpm out.
BUILD_HOME="$SANDBOX/build-home"
CACHE_DIR="$SANDBOX/caches"
mkdir -p "$BUILD_HOME" "$CACHE_DIR/clang" "$CACHE_DIR/swift" "$CACHE_DIR/cargo"
echo "building (nice -n 15 swift build -j 2)…"
env HOME="$BUILD_HOME" \
    CLANG_MODULE_CACHE_PATH="$CACHE_DIR/clang" \
    SWIFTPM_MODULECACHE_OVERRIDE="$CACHE_DIR/swift" \
    CARGO_HOME="$CACHE_DIR/cargo" \
    nice -n 15 swift build -j 2 --package-path "$APP_DIR"
BIN="$APP_DIR/.build/debug/AuxesisMac"
[ -x "$BIN" ] || { echo "run-auxesis-mac: $BIN missing after build" >&2; exit 1; }

env HOME="$HOME_SANDBOX" AUXESIS_HOME="$HOME_SANDBOX" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 "$AUXD" >"$SANDBOX/auxd.log" 2>&1 &
AUXD_PID=$!

PORT=""
for _ in $(seq 1 100); do
  PORT="$(sed -n 's/.*auxd api on http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$SANDBOX/auxd.log" | head -1)"
  [ -n "$PORT" ] && break
  if ! kill -0 "$AUXD_PID" 2>/dev/null; then
    echo "run-auxesis-mac: auxd exited before listening:" >&2
    cat "$SANDBOX/auxd.log" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [ -z "$PORT" ]; then
  echo "run-auxesis-mac: auxd never reported a port" >&2
  cat "$SANDBOX/auxd.log" >&2 || true
  exit 1
fi

echo "sandbox auxd: home=$HOME_SANDBOX port=$PORT pid=$AUXD_PID"
echo "token mode: $(stat -f '%Sp' "$HOME_SANDBOX/api.token") (auxd writes it 0600)"

APP_ENV=(HOME="$HOME_SANDBOX" AUXESIS_HOME="$HOME_SANDBOX" AUXESIS_SANDBOX=1 AUXESIS_API_PORT="$PORT" AUXESIS_API_BASE="http://127.0.0.1:$PORT")

# A bare SwiftPM executable does not reliably come to the front (an early
# NSApp.activate can be ignored). The app retries by itself; this System Events
# nudge is the belt-and-braces fallback and may need Automation permission —
# failures are never fatal.
bring_to_front() {
  osascript -e 'tell application "System Events" to set frontmost of (first process whose name contains "Auxesis") to true' \
    >/dev/null 2>&1 || true
}

# The run modes are a function (body not re-indented) so that a UI smoke script
# can source this file for the sandbox, the build and the auxd start, and drive the
# app itself. Executed directly, nothing changes.
run_app_modes() {
if [ "${1:-}" = "--shot" ]; then
  SHOTS="${AUXESIS_MAC_SHOTS:-$APP_DIR/shots}"
  mkdir -p "$SHOTS"
  LOG="$SANDBOX/app.log"
  env "${APP_ENV[@]}" "$BIN" >"$LOG" 2>&1 &
  APP_PID=$!
  WID=""
  for _ in $(seq 1 100); do
    WID="$(sed -n 's/.*AUXESIS_MAC_WINDOW_ID=\([0-9][0-9]*\).*/\1/p' "$LOG" | head -1)"
    [ -n "$WID" ] && break
    kill -0 "$APP_PID" 2>/dev/null || break
    sleep 0.1
  done
  # READY/window exist by now: ask the system to put the app in front.
  bring_to_front
  sleep 4
  if [ -n "$WID" ] && screencapture -x -o -l "$WID" "$SHOTS/01-thread.png" 2>/dev/null; then
    sips -Z 1100 "$SHOTS/01-thread.png" >/dev/null 2>&1 || true
    echo "wrote $SHOTS/01-thread.png (window $WID)"
  else
    echo "screencapture unavailable or not permitted — no screenshot (not fatal)"
  fi
  kill "$APP_PID" 2>/dev/null || true
  wait "$APP_PID" 2>/dev/null || true
  APP_PID=""
  exit 0
fi

echo "running the app — quit with ⌘Q (Ctrl-C stops the sandbox too)"
LOG="$SANDBOX/app.log"
env "${APP_ENV[@]}" "$BIN" >"$LOG" 2>&1 &
APP_PID=$!

READY=""
for _ in $(seq 1 100); do
  grep -q 'AUXESIS_MAC_READY' "$LOG" 2>/dev/null && READY=1 && break
  kill -0 "$APP_PID" 2>/dev/null || break
  sleep 0.1
done
if [ -n "$READY" ]; then
  echo "app ready — bringing it to the front"
  bring_to_front
else
  echo "app did not print READY; see $LOG" >&2
fi

wait "$APP_PID" || true
APP_PID=""
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  run_app_modes "$@"
fi
