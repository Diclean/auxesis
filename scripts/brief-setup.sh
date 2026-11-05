#!/usr/bin/env bash
# One command turns on the 08:00 morning brief from a simulated mailbox.
#   scripts/brief-setup.sh --sandbox   # needs AUXESIS_SANDBOX=1 and AUXESIS_HOME
#   scripts/brief-setup.sh --owner [--imap-port N]
# For one AUXESIS_HOME (default ~/.auxesis with --owner): keeps aux-fakemail (fictional
# mails, loopback, one new a day) running as LaunchAgent com.auxesis.fakemail (--sandbox:
# plist written, process started directly); adds the mail account `fakemail` to config.toml
# (`aux mail add` cannot target loopback) and its fictional password to .env (0600); sets
# [brief] enabled = true, time = "08:00" (config.toml.bak kept); writes gateways.toml (0600)
# only when env AUX_OWNER_HANDLES (comma list), AUX_AGENT_HANDLE and AUX_CHAT_GUID are all
# set (env only, so they never sit in `ps`). Re-running changes nothing. Handles are never
# printed. No macOS permission is changed. If another program holds the IMAP port, it stops
# with an error. Binary: AUXFAKEMAIL, else target/release/aux-fakemail, else PATH.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/guard.sh
source "$REPO_ROOT/scripts/lib/guard.sh"

LABEL="com.auxesis.fakemail" ACCOUNT="fakemail" MODE="sandbox"
IMAP_PORT="${AUX_FAKEMAIL_IMAP_PORT:-14143}" # fixed loopback port
OWNER_HANDLES=()
[ -n "${AUX_OWNER_HANDLES:-}" ] && IFS=',' read -r -a OWNER_HANDLES <<<"$AUX_OWNER_HANDLES"
AGENT_HANDLE="${AUX_AGENT_HANDLE:-}" CHAT_GUID="${AUX_CHAT_GUID:-}"

die() { echo "brief-setup: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --sandbox) MODE="sandbox" ;;
    --owner) MODE="owner" ;;
    --imap-port)
      [ $# -ge 2 ] || die "--imap-port needs a value"
      IMAP_PORT="$2"
      shift
      ;;
    *) die "unknown option $1" ;;
  esac
  shift
done

# Refuse a real HOME unless --owner.
if [ "$MODE" = "sandbox" ]; then
  [ "${AUXESIS_SANDBOX:-}" = "1" ] || die "refusing: AUXESIS_SANDBOX is not 1 (pass --owner to set up the real Mac)"
  [ -n "${AUXESIS_HOME:-}" ] || die "refusing: AUXESIS_HOME must be set in a sandbox"
  # guard.sh already refused a HOME that is the real home; check AUXESIS_HOME too.
  ! guard_under "$AUXESIS_HOME" "$(guard_real_home)/.auxesis" || die "refusing: AUXESIS_HOME is the real ~/.auxesis"
else
  [ "${AUXESIS_SANDBOX:-}" != "1" ] || die "--owner contradicts AUXESIS_SANDBOX=1"
  AUXESIS_HOME="${AUXESIS_HOME:-$HOME/.auxesis}"
fi
HOME_DIR="$AUXESIS_HOME"
[[ "$IMAP_PORT" =~ ^[0-9]+$ && "$IMAP_PORT" -ge 1024 ]] || die "the IMAP port must be a number, 1024 or higher"

BIN="${AUXFAKEMAIL:-}"
[ -n "$BIN" ] || BIN="$REPO_ROOT/target/release/aux-fakemail"
[ -x "$BIN" ] || BIN="$(command -v aux-fakemail || true)"
[ -x "$BIN" ] || die "no aux-fakemail binary (build it, or set AUXFAKEMAIL=<path>)"
case "$BIN" in /*) ;; *) die "AUXFAKEMAIL must be an absolute path" ;; esac

STATE="$HOME_DIR/fakemail" CONFIG="$HOME_DIR/config.toml" CHANGED=0

# Atomic text write: the file only changes when the content differs.
put_file() { # path mode content
  if [ -f "$1" ] && [ "$(cat "$1")" = "$3" ]; then return 0; fi
  (umask 077 && printf '%s\n' "$3" >"$1.tmp.$$")
  chmod "$2" "$1.tmp.$$" && mv "$1.tmp.$$" "$1" && CHANGED=1
}

# The simulator's state must be a real directory: a symlink could send its writes elsewhere.
[ ! -L "$STATE" ] || die "$STATE is a symlink; refusing"
mkdir -p "$HOME_DIR" "$STATE"
# The fictional demo set (possible new clients included), written once and then kept.
if [ ! -f "$STATE/mailbox.json" ]; then
  "$BIN" demo --dir "$STATE" >/dev/null || die "could not write the demo mailbox"
  CHANGED=1
fi
chmod 700 "$STATE"

# 1. Keep aux-fakemail running.
tcp_up() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
# True only when the port's listener is our aux-fakemail: it writes $STATE/pid once bound.
ours() {
  local pid
  pid="$(cat "$STATE/pid" 2>/dev/null)" && [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [[ "$(ps -o comm= -p "$pid" 2>/dev/null)" == *aux-fakemail ]] || return 1
  lsof -nP -a -p "$pid" -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}
busy_die() { die "port $IMAP_PORT is used by another program; pass --imap-port N (no mail config was written)"; }
command -v lsof >/dev/null || die "lsof is needed to check the port"
if tcp_up "$IMAP_PORT" && ! ours "$IMAP_PORT"; then busy_die; fi

ARGS=(serve --dir "$STATE" --imap-port "$IMAP_PORT" --smtp-port 0 --daily-mail)
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST="$PLIST_DIR/$LABEL.plist"
mkdir -p "$PLIST_DIR"
ARGS_XML="$(printf '<string>%s</string>' "${ARGS[@]}")"
PLIST_BODY="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<plist version=\"1.0\"><dict><key>Label</key><string>$LABEL</string>
<key>ProgramArguments</key><array><string>$BIN</string>$ARGS_XML</array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>$STATE/fakemail.log</string>
<key>StandardErrorPath</key><string>$STATE/fakemail.log</string></dict></plist>"
PLIST_OLD=""
[ -f "$PLIST" ] && PLIST_OLD="$(cat "$PLIST")"
put_file "$PLIST" 644 "$PLIST_BODY"

if [ "$MODE" = "owner" ]; then
  DOMAIN="gui/$(id -u)"
  [ "$PLIST_OLD" = "$PLIST_BODY" ] || launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  if ! launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; then
    launchctl bootstrap "$DOMAIN" "$PLIST" || die "launchctl bootstrap failed"
    CHANGED=1
  fi
elif ! ours "$IMAP_PORT"; then
  # Sandbox: start the process directly, no LaunchAgent; aux-fakemail writes $STATE/pid.
  (
    cd "$STATE"
    env -i HOME="$HOME" AUXESIS_HOME="$AUXESIS_HOME" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 \
      nohup "$BIN" "${ARGS[@]}" </dev/null >>"$STATE/fakemail.log" 2>&1 &
  )
  CHANGED=1
fi

for _ in $(seq 1 100); do
  ours "$IMAP_PORT" && break
  sleep 0.2
done
if ! ours "$IMAP_PORT"; then
  ! tcp_up "$IMAP_PORT" || busy_die
  die "aux-fakemail is not listening on 127.0.0.1:$IMAP_PORT (see $STATE/fakemail.log)"
fi

# 2 + 3. config.toml: mail account and [brief]. A new config names `main` as
# the chief, as the app writes one (without the key the home reads as an older
# install); an existing config keeps what it has.
if [ ! -e "$CONFIG" ] && [ ! -L "$CONFIG" ]; then
  (set -C && umask 077 && printf 'version = 1\ndefault_agent = "main"\n' >"$CONFIG")
fi
chmod 600 "$CONFIG"
WORK="$(mktemp "$CONFIG.edit.XXXXXX")"
trap 'rm -f "$WORK"' EXIT
cp "$CONFIG" "$WORK"

# TODO: set_key matches bare keys only; a quoted key ("enabled" = true) would be duplicated.
# set_key <section> <key> <value>: replace the key in [section], or add it (or the section).
set_key() {
  local out="$WORK.next"
  awk -v sec="$1" -v key="$2" -v val="$3" '
    BEGIN { hdr = "[" sec "]"; line = key " = " val }
    /^[[:space:]]*\[/ { if (insec && !done) { print line; done = 1 } insec = ($0 ~ "^[[:space:]]*" "\\[" sec "\\][[:space:]]*(#.*)?$"); if (insec) seen = 1 }
    insec && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" { if (!done) { print line; done = 1 } next }
    { print }
    END { if (insec && !done) print line; if (!seen) { if (NR) print ""; print hdr; print line } }
  ' "$WORK" >"$out"
  mv "$out" "$WORK"
}

set_key brief enabled true
set_key brief time '"08:00"'

if ! grep -q "^id = \"$ACCOUNT\"" "$WORK"; then
  if grep -q '^\[\[connectors\.mail\.accounts\]\]' "$WORK"; then
    die "config.toml already has a mail account; remove it first (the brief reads only the simulated mailbox)"
  fi
  {
    grep -q '^\[connectors\.mail\]' "$WORK" || printf '\n[connectors.mail]\n'
    printf '\n[[connectors.mail.accounts]]\nid = "%s"\nemail = "owner@mailsim.test"\n\n[connectors.mail.accounts.imap]\nhost = "127.0.0.1"\nport = %s\nsecurity = "tls"\nca_file = "%s"\n' \
      "$ACCOUNT" "$IMAP_PORT" "$STATE/cert.pem"
  } >>"$WORK"
fi

if ! cmp -s "$CONFIG" "$WORK"; then
  [ ! -s "$CONFIG" ] || cp -p "$CONFIG" "$CONFIG.bak"
  chmod 600 "$WORK"
  mv "$WORK" "$CONFIG"
  CHANGED=1
fi

# The simulator accepts any password; a fixed fictional one, never a real secret.
if ! grep -q '^AUX_MAIL_FAKEMAIL=' "$HOME_DIR/.env" 2>/dev/null; then
  (umask 077 && printf 'AUX_MAIL_FAKEMAIL=fictional-password\n' >>"$HOME_DIR/.env")
  CHANGED=1
fi
chmod 600 "$HOME_DIR/.env"

# 4. gateways.toml.
if [ ${#OWNER_HANDLES[@]} -gt 0 ] || [ -n "$AGENT_HANDLE" ] || [ -n "$CHAT_GUID" ]; then
  [ ${#OWNER_HANDLES[@]} -gt 0 ] && [ -n "$AGENT_HANDLE" ] && [ -n "$CHAT_GUID" ] ||
    die "iMessage needs an owner handle, an agent handle and a chat guid together"
  LIST=""
  for h in "${OWNER_HANDLES[@]}" "$AGENT_HANDLE" "$CHAT_GUID"; do
    # Nothing that could break out of a TOML string; the value is never printed.
    [[ -n "$h" && ! "$h" =~ [[:cntrl:]\"\\] ]] || die "a handle or guid has a character that is not allowed"
  done
  for h in "${OWNER_HANDLES[@]}"; do LIST="$LIST${LIST:+, }\"$h\""; done
  BLOCK="[imessage]
enabled = true
owner_handles = [$LIST]
chat_guid = \"$CHAT_GUID\"
agent_handle = \"$AGENT_HANDLE\"
mode = \"apple_id\"
min_gap_secs = 15"
  GATEWAYS="$HOME_DIR/gateways.toml"
  EXISTING=""
  [ -f "$GATEWAYS" ] && EXISTING="$(cat "$GATEWAYS")"
  case "$EXISTING" in
    *"$BLOCK"*) ;;
    *"[imessage]"*) die "gateways.toml already has a different [imessage] section; edit it by hand" ;;
    *) put_file "$GATEWAYS" 600 "${EXISTING:+$EXISTING$'\n\n'}$BLOCK" ;;
  esac
  chmod 600 "$GATEWAYS"
  echo "brief-setup: gateways.toml has the [imessage] section (mode 0600)."
fi

# 5. What is left for the owner.
echo "brief-setup: $([ "$CHANGED" = 1 ] && echo "done: mailbox, mail account and 08:00 brief are set up." || echo "nothing to change.")"
cat <<EOF
brief-setup: still to do by hand (this script never changes a macOS permission):
  - Full Disk Access for the aux-imessage helper ONLY (System Settings > Privacy & Security).
  - Allow the helper to control Messages (Automation) when macOS asks once.
  - Restart auxd so it reads the new config (scripts/run-dev.sh), then: aux brief status
EOF
