#!/usr/bin/env bash
# Acceptance test for scripts/brief-setup.sh (sandbox only; --no-build reuses the last
# build; AUXD, AUX, AUXFAKEMAIL skip the build). Refusal without a sandbox, refusal when
# another program holds the port, two runs that change nothing, then a sandbox auxd: schedule ON at 08:00, brief lists the fictional mail.
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The shared build wrapper, when the machine configures one (AUX_OPS_DIR).
MAC_BUILD="${MAC_BUILD:-${AUX_OPS_DIR:+$AUX_OPS_DIR/scripts/mac-build.sh}}"
SETUP="$REPO_ROOT/scripts/brief-setup.sh"
# shellcheck source=lib/guard.sh
source "$REPO_ROOT/scripts/lib/guard.sh"
BUILD=1; [ "${1:-}" != "--no-build" ] || BUILD=0
# The simulated mailbox the script writes holds twelve mails, four of them
# read: the brief counts eight unread.
EXPECT_UNREAD=8

STEP="setup" WORK="" AUXD_PID="" LISTENER_PID=""
red() { echo "RED $STEP: $*"; exit 1; }
cleanup() {
  local pid
  for pid in "$AUXD_PID" "$LISTENER_PID" "$(cat "$WORK/home/.auxesis/fakemail/pid" 2>/dev/null || true)"; do
    { [ -z "$pid" ] || { kill "$pid" && wait "$pid"; }; } 2>/dev/null || true
  done
  [ -z "$WORK" ] || rm -rf "$WORK"
}
trap 'red "unexpected failure (exit $?)"' ERR
trap cleanup EXIT
trap 'exit 143' TERM INT HUP

if [ "$BUILD" = 1 ] && [ -z "${AUXD:-}" ]; then
  builder=(cargo)
  [ ! -x "$MAC_BUILD" ] || builder=("$MAC_BUILD")
  (cd "$REPO_ROOT" && "${builder[@]}" build -p auxd -p aux-cli -p aux-fakemail --locked --release) || red "build failed"
fi
target="$REPO_ROOT/target"
if [ -x "$MAC_BUILD" ]; then
  key="$(printf '%s' "$(cd "$REPO_ROOT" && pwd -P)" | shasum -a 1 | cut -c1-12)"
  target="${AUX_MAC_TARGET:-$HOME/Library/Caches/auxesis-mac-build/targets/$key}"
fi
AUXD="${AUXD:-$target/release/auxd}" AUX="${AUX:-$target/release/aux}"
AUXFAKEMAIL="${AUXFAKEMAIL:-$target/release/aux-fakemail}"
for bin in "$AUXD" "$AUX" "$AUXFAKEMAIL"; do [ -x "$bin" ] || red "missing binary $bin"; done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/brief-setup-test.XXXXXX")"
HOME_DIR="$WORK/home/.auxesis"

# A free loopback port: probe upward from a random start.
free_port() {
  local p=$((20000 + RANDOM % 20000))
  while (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; do p=$((p + 1)); done
  echo "$p"
}
IMAP="$(free_port)"

sbx() {
  env -i HOME="$WORK/home" AUXESIS_HOME="$HOME_DIR" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" AUXFAKEMAIL="$AUXFAKEMAIL" "$@"
}
# For a background daemon: exec keeps one pid, so cleanup kills auxd itself, not a
# subshell that would leave it running (six orphan auxd found 2026-10-30).
sbx_exec() { exec env -i HOME="$WORK/home" AUXESIS_HOME="$HOME_DIR" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" AUXFAKEMAIL="$AUXFAKEMAIL" "$@"; }
setup() { sbx AUX_FAKEMAIL_IMAP_PORT="$IMAP" ${AUX_OWNER_HANDLES:+AUX_OWNER_HANDLES="$AUX_OWNER_HANDLES" AUX_AGENT_HANDLE="$AUX_AGENT_HANDLE" AUX_CHAT_GUID="$AUX_CHAT_GUID"} "$SETUP" --sandbox "$@"; }
sums() { (cd "$WORK/home" && find . -type f ! -name fakemail.log ! -name '*.tmp.*' -print0 | sort -z | xargs -0 shasum -a 256); }

STEP="refuse-without-sandbox"
if env -i HOME="$WORK/home" AUXESIS_HOME="$HOME_DIR" PATH="/usr/bin:/bin" "$SETUP" --sandbox >/dev/null 2>&1; then
  red "ran without AUXESIS_SANDBOX=1"
fi

STEP="refuse-symlinked-state"
mkdir -p "$HOME_DIR" "$WORK/elsewhere"
ln -s "$WORK/elsewhere" "$HOME_DIR/fakemail"
if setup >"$WORK/symlink.log" 2>&1; then red "ran with a symlinked fakemail dir"; fi
[ ! -e "$WORK/elsewhere/mailbox.json" ] || red "wrote through the symlinked fakemail dir"
rm "$HOME_DIR/fakemail"

STEP="port-collision"
# Another program on the port: setup must fail, name the port, and write no mail config.
CLASH="$(free_port)"
python3 -I -c 'import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(); time.sleep(120)' "$CLASH" &
LISTENER_PID=$!
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$CLASH") 2>/dev/null && break; sleep 0.1; done
mkdir -p "$WORK/clash/.auxesis"
if env -i HOME="$WORK/clash" AUXESIS_HOME="$WORK/clash/.auxesis" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 \
  PATH="/usr/bin:/bin:/usr/sbin:/sbin" AUXFAKEMAIL="$AUXFAKEMAIL" "$SETUP" --sandbox --imap-port "$CLASH" \
  >"$WORK/clash.log" 2>&1; then red "setup succeeded on a port another program holds"; fi
grep -q "another program" "$WORK/clash.log" || red "no plain port message: $(tail -n 2 "$WORK/clash.log")"
[ ! -e "$WORK/clash/.auxesis/config.toml" ] || red "a config was written despite the port clash"
kill "$LISTENER_PID" 2>/dev/null; wait "$LISTENER_PID" 2>/dev/null || true; LISTENER_PID=""

STEP="setup-twice"
# An existing config with another key and a comment: both must survive.
mkdir -p "$HOME_DIR"
printf '# owner comment\n[ui]\nlanguage = "en"\n\n[brief]\nenabled = false\n' >"$HOME_DIR/config.toml"
# Fictional handles, from the environment only (never argv).
export AUX_OWNER_HANDLES="+33600000001,owner@example.test" AUX_AGENT_HANDLE="agent@example.test" \
  AUX_CHAT_GUID="iMessage;-;agent@example.test"
setup >"$WORK/run1.log" 2>&1 || red "first run failed: $(tail -n 3 "$WORK/run1.log")"
before="$(sums)"
setup >"$WORK/run2.log" 2>&1 || red "second run failed: $(tail -n 3 "$WORK/run2.log")"
[ "$before" = "$(sums)" ] || red "the second run changed a file"
has() { grep -q -- "$1" "$2" || red "$3"; }
has 'nothing to change' "$WORK/run2.log" "second run did not say it was a no-op"
cfg="$HOME_DIR/config.toml"
grep -q "owner@example.test" "$HOME_DIR/gateways.toml" || red "gateways.toml has no owner handle"
has '^enabled = true' "$cfg" "[brief] not enabled"
has '^time = "08:00"' "$cfg" "[brief] time is not 08:00"
has '^# owner comment' "$cfg" "a comment was lost"
has '^language = "en"' "$cfg" "another key was clobbered"
[ "$(grep -c '^\[brief\]' "$cfg")" = 1 ] || red "[brief] is duplicated"
[ -f "$cfg.bak" ] || red "no config.toml.bak"
[ "$(stat -f %Lp "$HOME_DIR/gateways.toml")" = "600" ] || red "gateways.toml is not 0600"
[ "$(stat -f %Lp "$HOME_DIR/.env")" = "600" ] || red ".env is not 0600"
[ -f "$WORK/home/Library/LaunchAgents/com.auxesis.fakemail.plist" ] || red "no LaunchAgent plist in the sandbox HOME"
! grep -q 'owner@example.test' "$WORK/run1.log" "$WORK/run2.log" || red "a handle reached the log"

STEP="daemon"
# The brief skips inside quiet hours; an empty window is never quiet (as hero-smoke).
printf '\n[quiet]\nstart = "00:00"\nend = "00:00"\n' >>"$cfg"
sbx_exec "$AUXD" >"$WORK/auxd.log" 2>&1 &
AUXD_PID=$!
PORT=""
for _ in $(seq 1 150); do
  PORT="$(sed -n 's/.*auxd api on http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$WORK/auxd.log" | head -1)"
  [ -n "$PORT" ] && break
  kill -0 "$AUXD_PID" 2>/dev/null || red "auxd exited: $(tail -n 3 "$WORK/auxd.log")"
  sleep 0.2
done
[ -n "$PORT" ] || red "auxd never announced its port"
cli() { env -i HOME="$WORK/home" AUXESIS_HOME="$HOME_DIR" AUXESIS_SANDBOX=1 AUXESIS_API_PORT="$PORT" "$AUX" "$@"; }

status="$(cli brief status 2>&1)" || red "aux brief status failed: $status"
[[ "$status" != *"schedule is off"* ]] || red "the schedule is off: $status"
[[ "$status" == *"(daily 08:00)"* ]] || red "no daily 08:00 schedule: $status"
[[ "$status" == *"next scheduled: "*08:00* ]] || red "next run is not at 08:00: $status"

STEP="brief"
brief="$(cli brief now 2>"$WORK/brief.err")" || red "aux brief now failed: $(head -c 300 "$WORK/brief.err")"
# The mail section counts the unread mails of the simulated mailbox. The
# wording is BriefUnreadMany ("{0} unread"), changed by #245 from
# "new message(s)."; the demo set holds twelve mails, four of them read.
grep -qxF "$EXPECT_UNREAD unread" <<<"$brief" || red "no mail section: $(head -c 300 <<<"$brief")"
# The mail line itself, sender and all: the name alone could also come from
# the prospects section, which is not the mail list.
[[ "$brief" == *"• Jonas Sample <jonas@brightpath.example>"* ]] || red "the fictional demo mail is not in the brief: $(head -c 400 <<<"$brief")"
[[ "$brief" == *"Possible new clients"* ]] || red "no possible new clients from the demo set: $(head -c 600 <<<"$brief")"

echo "GREEN brief-setup: idempotent, schedule on at 08:00, brief lists the simulated mail"
