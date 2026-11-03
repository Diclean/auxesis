#!/usr/bin/env bash
# The owner's daily launcher: build auxd and the Mac app from source, start
# auxd, open the app connected to it.
#
#   scripts/run-dev.sh             # owner: your real ~/.auxesis and normal port
#   scripts/run-dev.sh --sandbox   # throwaway home, ephemeral port, deleted on exit
#   scripts/run-dev.sh --no-build  # reuse the last builds
#
# auxd is built with cargo, or with the shared build wrapper (one build at a
# time, shared target dir) when the machine configures one; AUXD=<path> skips
# that build and uses the given binary.
# The sandbox run is delegated to apps/auxesis-mac/scripts/run-auxesis-mac.sh;
# the owner run builds the bundle with make-app.sh and opens it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$REPO_ROOT/apps/auxesis-mac"
# The shared build wrapper, when the machine configures one (AUX_OPS_DIR).
MAC_BUILD="${MAC_BUILD:-${AUX_OPS_DIR:+$AUX_OPS_DIR/scripts/mac-build.sh}}"
# shellcheck source=lib/guard.sh
source "$REPO_ROOT/scripts/lib/guard.sh"
MODE=owner
BUILD=1
for arg in "$@"; do
  case "$arg" in
    --sandbox) MODE=sandbox ;;
    --no-build) BUILD=0 ;;
    -h | --help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "run-dev: unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

TARGET="$REPO_ROOT/target"
if [ -x "$MAC_BUILD" ]; then
  # Same per-worktree target as mac-build.sh: keyed by the physical root path.
  KEY="$(printf '%s' "$(cd "$REPO_ROOT" && pwd -P)" | shasum -a 1 | cut -c1-12)"
  TARGET="${AUX_MAC_TARGET:-$HOME/Library/Caches/auxesis-mac-build/targets/$KEY}"
fi

if [ "$BUILD" = 1 ] && [ -z "${AUXD:-}" ]; then
  echo "building auxd (release)…"
  if [ -x "$MAC_BUILD" ]; then
    (cd "$REPO_ROOT" && "$MAC_BUILD" build -p auxd -p aux-cli --release)
  else
    (cd "$REPO_ROOT" && cargo build -p auxd -p aux-cli --release)
  fi
fi
AUXD="${AUXD:-$TARGET/release/auxd}"
[ -x "$AUXD" ] || { echo "run-dev: no auxd at $AUXD (build it, or set AUXD=<path>)" >&2; exit 1; }

# True when /v1/health answers on the port, authenticated with the token file.
health_ok() {
  [ -r "$2" ] || return 1
  # The bearer header goes to curl on stdin (`--config -`), never on its argv.
  printf 'header = "Authorization: Bearer %s"\n' "$(tr -d '\n' < "$2")" \
    | curl --config - -fsS -m 3 "http://127.0.0.1:$1/v1/health" >/dev/null 2>&1
}

# Polls /v1/health every 0.2 s for up to 15 s; true as soon as it answers.
wait_health() {
  local deadline=$((SECONDS + 15))
  until health_ok "$1" "$2"; do
    (( SECONDS >= deadline )) && return 1
    sleep 0.2
  done
}

# The sandbox run: run-auxesis-mac.sh starts a throwaway auxd and the app. It
# prints `sandbox auxd: home=<dir> port=<n> pid=<n>`; that line is where we
# check /v1/health while the app is open.
run_sandbox() {
  local line home port
  # Global on purpose: the EXIT trap runs after this function has returned.
  SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/run-dev.XXXXXX")"
  trap 'rm -rf "${SANDBOX:-/nonexistent}"' EXIT
  mkdir -p "$SANDBOX/home"
  if guard_under "$SANDBOX" "$(guard_real_home)"; then
    echo "run-dev: refusing: sandbox $SANDBOX resolves into the real home" >&2
    exit 1
  fi
  echo "stop: quit the app with ⌘Q (or Ctrl-C here); the sandbox auxd stops with it"
  env -i PATH="$PATH" TMPDIR="$SANDBOX" HOME="$SANDBOX/home" \
    AUXESIS_HOME="$SANDBOX/home/.auxesis" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 \
    AUXESIS_MAC_AUXD="$AUXD" "$APP_DIR/scripts/run-auxesis-mac.sh" 2>&1 |
    while IFS= read -r line; do
      echo "$line"
      case "$line" in
        "sandbox auxd: "*)
          home="$(printf '%s\n' "$line" | sed -n 's/.*home=\([^ ]*\) port=.*/\1/p')"
          port="$(printf '%s\n' "$line" | sed -n 's/.*port=\([0-9][0-9]*\) pid=.*/\1/p')"
          if health_ok "$port" "$home/api.token"; then
            echo "run-dev: auxd answered /v1/health on 127.0.0.1:$port"
          else
            echo "run-dev: auxd did not answer /v1/health on 127.0.0.1:$port" >&2
          fi
          ;;
      esac
    done
}

# The owner run: the real AUXESIS_HOME and the normal port. A running auxd is
# reused, never a second one.
run_owner() {
  local aux_home port auxd_pid="" i
  aux_home="${AUXESIS_HOME:-$HOME/.auxesis}"
  # A fresh Mac has no home yet, and the daemon log is written into it.
  mkdir -p -m 700 "$aux_home"
  port="$(sed -n 's/^api_port *= *\([0-9][0-9]*\).*/\1/p' "$aux_home/config.toml" 2>/dev/null | head -1)"
  port="${port:-2893}"
  if [ "$BUILD" = 1 ]; then
    "$APP_DIR/scripts/make-app.sh"
  fi
  # A port that accepts connections belongs to a running auxd: give it 15 s to
  # answer, and never start a second one on top of it.
  if nc -z 127.0.0.1 "$port" 2>/dev/null && ! wait_health "$port" "$aux_home/api.token"; then
    echo "run-dev: 127.0.0.1:$port accepts connections but /v1/health did not answer in 15 s" >&2
    exit 1
  fi
  if health_ok "$port" "$aux_home/api.token"; then
    echo "run-dev: auxd already running on 127.0.0.1:$port — reusing it"
    echo "stop: quit Auxesis (⌘Q); the running auxd keeps running"
  else
    env -u AUXESIS_SANDBOX -u AUXESIS_API_PORT AUXESIS_HOME="$aux_home" \
      nohup "$AUXD" >>"$aux_home/auxd-dev.log" 2>&1 &
    auxd_pid=$!
    for i in $(seq 1 50); do
      health_ok "$port" "$aux_home/api.token" && break
      kill -0 "$auxd_pid" 2>/dev/null || { echo "run-dev: auxd exited; see $aux_home/auxd-dev.log" >&2; exit 1; }
      sleep 0.2
    done
    health_ok "$port" "$aux_home/api.token" || { echo "run-dev: auxd did not answer /v1/health on 127.0.0.1:$port" >&2; exit 1; }
    echo "run-dev: auxd started on 127.0.0.1:$port (pid $auxd_pid)"
    echo "stop: quit Auxesis (⌘Q), then: kill $auxd_pid"
  fi
  open "$APP_DIR/build/Auxesis.app"
}

if [ "$MODE" = sandbox ]; then
  run_sandbox
else
  run_owner
fi
