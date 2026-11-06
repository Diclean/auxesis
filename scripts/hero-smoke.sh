#!/usr/bin/env bash
# Hero path, sandbox only. One private chat turn through a real auxd with the
# fake provider. `aux brief now` builds a brief from a fictional calendar
# snapshot and a loopback aux-fakemail mailbox, in the same run. `aux crm
# timeline refresh` puts one fixture mail and one fixture meeting on the client
# card (GET /v1/clients/{id}), then `aux skill run log-interaction` logs one
# interaction that shows on the card. `/invite` raises one approval card in
# the app (a fake /v1/events client) and nothing reaches the fake SMTP; a no sends
# nothing; a yes sends exactly one mail with a text/calendar METHOD:REQUEST part to
# the client, whose card shows the client's own start and whose .ics carries that
# converted hour; a repeat yes sends nothing more. `aux skill run collect-receipts`
# collects a mailed PDF receipt, a fake bridge reads it, `aux docs list` shows it
# linked to its client, `aux docs export` writes the CSV and the original. A
# fixture stdio MCP server installs disabled, one approval starts it, a chat call
# sends an IBAN token and never the raw value, and a widened tool list waits for
# a second yes. Prints one GREEN or RED line; exit 0 only when GREEN.
#
#   scripts/hero-smoke.sh                        # build auxd, aux, aux-fakemail, then run
#   AUXD=<bin> AUX=<bin> AUXFAKEMAIL=<bin> scripts/hero-smoke.sh   # reuse binaries, no build
#   scripts/hero-smoke.sh --no-build             # reuse the last build
#
# Every auxd, aux and aux-fakemail call runs with a literal sandbox env (HOME,
# AUXESIS_HOME and TMPDIR under a fresh mktemp dir, AUXESIS_SANDBOX=1,
# AUXESIS_API_PORT=0). The one CLI call that reaches auxd uses the loopback port
# auxd announced; the sandbox guard needs a real port for a client. A trap stops
# auxd, aux-fakemail, the provider recorder, the fake app, any open turn and the
# stdio child, and deletes the temp dir. The real home and the real daemon
# port are never used.
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The shared build wrapper, when the machine configures one (AUX_OPS_DIR).
MAC_BUILD="${MAC_BUILD:-${AUX_OPS_DIR:+$AUX_OPS_DIR/scripts/mac-build.sh}}"
FIXTURES="$REPO_ROOT/scripts/fixtures/hero-m2"
# Guard only: inert here (AUXESIS_SANDBOX is not set in this shell), so it
# never refuses an owner shell. guard_under checks the temp dirs below.
# shellcheck source=lib/guard.sh
source "$REPO_ROOT/scripts/lib/guard.sh"

# Invented data only. The contact is fictional; its e-mail address must not reach the
# provider raw. Its name does: private mode hides no name.
NAME="Camille Exemple"
EMAIL="camille@exemple.fr"
MESSAGE="Dis bonjour à $NAME, $EMAIL."

# Brief expectations, matching scripts/fixtures/hero-m2: one meeting today (the one
# tomorrow must not show) and three unread mails (the read one must not count).
EXPECT_MEETINGS=2
EXPECT_UNREAD=3
# CRM expectations: the fictional client, matched by exact address to the fixture mail
# (uid 1) and the fixture meeting; the owner's note is what the skill logs.
CLIENT_EMAIL="camille@exemple.test"
CLIENT_PHONE="+33612345678"
MAIL_SUBJECT="Kickoff agenda for Thursday"
MEETING_TITLE="Call with"
LOG_NOTE="Appel de suivi fictif"
# What `aux brief now` prints when today's brief already exists (CLI text).
ALREADY_TODAY="Today's brief already exists."
# A demo-world client (aux-fakemail world.json, Blueharbor) the owner invites.
INVITEE="Lea Blueharbor"
INVITEE_EMAIL="lea@blueharbor.example"
# A fictional IBAN, the MCP server's id, and its two tools. The fake provider
# only ever sees the kernel's token for the IBAN; the fixture logs what it gets.
M6_IBAN="FR76 3000 6000 0112 3456 7890 189"
M6_IBAN_DIGITS="FR7630006000011234567890189"
M6_SERVER="m6notes"
M6_AGENT="clients"
M6_READ="READ_NOTE"
M6_WRITE="WRITE_NOTE"
M6_MESSAGE="Lis la note pour l'IBAN $M6_IBAN. /mcp"

BUILD=1
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    -h | --help)
      sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "RED usage: unknown option $arg" >&2
      exit 2
      ;;
  esac
done

STEP="setup"
WORK=""
AUXD_PID=""
FAKEMAIL_PID=""
RECORDER_PID=""
APP_PID=""
TURN_PID=""
SMTP_PORT=""
APPROVAL_ID=""
TOKEN=""
PORT=""
IMAP_PORT=""
CA_FILE=""
HTTP_CODE=""
REPLY=""
CLIENT_ID=""
M6_HASH=""
M6_HASH2=""
red() {
  echo "RED $STEP: $*"
  exit 1
}
on_error() {
  red "unexpected failure (exit $1)"
}
# The stdio child is auxd's, but the trap stops it explicitly too: its pid is
# in the private temp dir the sandbox gave it, before "$WORK" is deleted.
cleanup_m6_child() {
  local file pid
  [ -n "$WORK" ] || return 0
  for file in "$WORK"/m6/tmp/aux-mcp-*/m6-pid; do
    [ -s "$file" ] || continue
    pid="$(cat "$file")"
    case "$pid" in
      '' | *[!0-9]*) continue ;;
    esac
    kill "$pid" 2>/dev/null || true
  done
}
cleanup() {
  local pid
  cleanup_m6_child
  for pid in "$TURN_PID" "$APP_PID" "$AUXD_PID" "$FAKEMAIL_PID" "$RECORDER_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [ -n "$WORK" ]; then
    rm -rf "$WORK"
  fi
}
trap 'on_error $?' ERR
trap cleanup EXIT

# Env prefix for every sandbox process: the sandbox line from `CONTRIBUTING.md`.
sbx() {
  env -i HOME="$WORK/home" AUXESIS_HOME="$WORK/home/.auxesis" \
    AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 "$@"
}

# The aux CLI calls auxd, so it needs the port auxd announced on loopback: the
# guard refuses port 0 for a client. That port is this sandbox daemon's own.
sbx_cli() {
  env -i HOME="$WORK/home" AUXESIS_HOME="$WORK/home/.auxesis" \
    AUXESIS_SANDBOX=1 AUXESIS_API_PORT="$PORT" "$AUX" "$@"
}

step_build() {
  STEP="build"
  if [ "$BUILD" = 1 ] && [ -z "${AUXD:-}" ]; then
    echo "building auxd, aux and aux-fakemail (release)…"
    if [ -x "$MAC_BUILD" ]; then
      (cd "$REPO_ROOT" && "$MAC_BUILD" build -p auxd -p aux-cli -p aux-fakemail --locked --release) || red "cargo build failed"
    else
      (cd "$REPO_ROOT" && cargo build -p auxd -p aux-cli -p aux-fakemail --locked --release) || red "cargo build failed"
    fi
  fi
  local target="$REPO_ROOT/target"
  if [ -x "$MAC_BUILD" ]; then
    # Same per-worktree target as mac-build.sh: keyed by the physical root path.
    local key
    key="$(printf '%s' "$(cd "$REPO_ROOT" && pwd -P)" | shasum -a 1 | cut -c1-12)"
    target="${AUX_MAC_TARGET:-$HOME/Library/Caches/auxesis-mac-build/targets/$key}"
  fi
  AUXD="${AUXD:-$target/release/auxd}"
  AUX="${AUX:-$target/release/aux}"
  AUXFAKEMAIL="${AUXFAKEMAIL:-$target/release/aux-fakemail}"
  [ -x "$AUXD" ] || red "no auxd at $AUXD (set AUXD=<path>)"
  [ -x "$AUX" ] || red "no aux at $AUX (set AUX=<path>)"
  [ -x "$AUXFAKEMAIL" ] || red "no aux-fakemail at $AUXFAKEMAIL (set AUXFAKEMAIL=<path>)"
}

step_sandbox() {
  STEP="sandbox"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/hero-smoke.XXXXXX")"
  if guard_under "$WORK" "$(guard_real_home)"; then
    red "refusing: sandbox $WORK resolves into the real home"
  fi
  mkdir -p "$WORK/home/.auxesis" "$WORK/m6/tmp"
  # The provider is a loopback recorder: it keeps every request body (what left
  # auxd) and echoes the last user text, as the fake provider did.
  cat >"$WORK/recorder.py" <<'PY'
import datetime, http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        open(sys.argv[1], "ab").write(body + b"\n")
        req = json.loads(body)
        msgs = req["messages"]
        last = max(i for i, m in enumerate(msgs) if m["role"] == "user")
        user = msgs[last]["content"]
        user = user if isinstance(user, str) else " ".join(p.get("text", "") for p in user)
        text = "[fake:fakey] " + user
        usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        offered = [t["function"]["name"] for t in req.get("tools") or []]
        msg, finish = {"role": "assistant", "content": text}, "stop"
        if "mcp__m6notes__READ_NOTE" in offered and "/mcp" in user:
            if any(m["role"] == "tool" for m in msgs[last + 1:]):
                msg["content"] = "M6 read done."
            else:
                # The provider only ever saw the kernel's IBAN token; pass that
                # token, never a value, so the child's log proves the gate.
                start = user.find("⟦IBAN_")
                end = user.find("⟧", start) + 1 if start >= 0 else 0
                token = user[start:end] if start >= 0 and end > start else "missing-token"
                call = {"id": "call-m6", "type": "function",
                        "function": {"name": "mcp__m6notes__READ_NOTE",
                                     "arguments": json.dumps({"query": token})}}
                msg, finish = {"role": "assistant", "content": "", "tool_calls": [call]}, "tool_calls"
        if "skill__send-invite" in offered and "/invite" in user:
            if any(m["role"] == "tool" for m in msgs[last + 1:]):
                msg["content"] = "Invitation sent."
            else:
                # The send-invite fill, tomorrow 10:00 local. The recipient is
                # invented: the runtime puts in the contact's own address.
                person = user.split("/invite", 1)[1].split(" tomorrow")[0].strip()
                start = (datetime.datetime.now().astimezone() + datetime.timedelta(days=1)).replace(hour=10, minute=0, second=0, microsecond=0)
                # The wall time, as the owner says it;
                # auxd resolves the zone. The invite is written in Paris time
                # and the model guesses a zone; the fixture client's card says
                # New York, so that stored zone must win and her own start show.
                start = start.replace(tzinfo=None)
                at, end = start.isoformat(), (start + datetime.timedelta(minutes=30)).isoformat()
                fill = {"slots": {"person": person, "when": at, "duration": "PT30M"}, "calls": [
                    {"tool": "apple_calendar_create_event", "arguments": {"title": "Meeting with " + person, "start": at, "end": end,
                                                                         "time_zone": "Europe/Paris", "attendee_time_zone": "Asia/Tokyo"}},
                    {"tool": "mail_send", "arguments": {"to": ["someone@invented.example"], "subject": "Invitation", "body": "Hello, see you tomorrow.", "ics": "event"}}]}
                call = {"id": "call-1", "type": "function", "function": {"name": "skill__send-invite", "arguments": json.dumps(fill)}}
                msg, finish = {"role": "assistant", "content": "", "tool_calls": [call]}, "tool_calls"
        if "skill__follow-up" in offered and "/followup" in user:
            # The pre-read's results come before the fill.
            if any(m["role"] == "tool" and not m.get("tool_call_id", "").startswith("pre_read_") for m in msgs[last + 1:]):
                msg["content"] = "Follow-up sent."
            else:
                # The follow-up fill. The recipient is invented: the
                # runtime puts in the contact's own address.
                person = user.split("/followup", 1)[1].strip()
                fill = {"slots": {"person": person, "topic": "the quote"}, "calls": [
                    {"tool": "mail_send", "arguments": {"to": ["someone@invented.example"], "subject": "Re: Quote",
                                                        "body": "Hello, a short follow-up on the quote."}}]}
                call = {"id": "call-1", "type": "function", "function": {"name": "skill__follow-up", "arguments": json.dumps(fill)}}
                msg, finish = {"role": "assistant", "content": "", "tool_calls": [call]}, "tool_calls"
        if "skill__reply-availability" in offered and "/availability" in user:
            if any(m["role"] == "tool" and not m.get("tool_call_id", "").startswith("pre_read_") for m in msgs[last + 1:]):
                msg["content"] = "Free times sent."
            else:
                # M4-3b: the model writes the marker; the runtime writes the times.
                person = user.split("/availability", 1)[1].strip()
                fill = {"slots": {"person": person}, "calls": [
                    {"tool": "mail_send", "arguments": {"to": ["someone@invented.example"], "subject": "Free times",
                                                        "body": "Hello,\n\nI am free:\n{free_times}\n\nBest"}}]}
                call = {"id": "call-1", "type": "function", "function": {"name": "skill__reply-availability", "arguments": json.dumps(fill)}}
                msg, finish = {"role": "assistant", "content": "", "tool_calls": [call]}, "tool_calls"
        if req.get("stream"):
            delta = dict(msg)
            if "tool_calls" in delta:
                delta["tool_calls"] = [dict(delta["tool_calls"][0], index=0)]
            chunk = {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}], "usage": usage}
            out, kind = ("data: " + json.dumps(chunk) + "\n\ndata: [DONE]\n\n").encode(), "text/event-stream"
        else:
            out = json.dumps({"choices": [{"index": 0, "message": msg, "finish_reason": finish}], "usage": usage}).encode()
            kind = "application/json"
        self.send_response(200); self.send_header("Content-Type", kind); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *args): pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
open(sys.argv[2], "w").write(str(server.server_address[1])); server.serve_forever()
PY
  python3 -I "$WORK/recorder.py" "$WORK/provider-bodies.jsonl" "$WORK/recorder.port" >/dev/null 2>&1 &
  RECORDER_PID=$!
  local i
  for i in $(seq 1 50); do [ -s "$WORK/recorder.port" ] && break; sleep 0.1; done
  [ -s "$WORK/recorder.port" ] || red "the provider recorder did not start"
  # The recorder runs on this Mac, so its model is priced at 0: since #87 an
  # unpriced model is refused while the money cap applies.
  # Private mode: the owner's contact's e-mail must be tokenised before the provider sees it; the name passes as written.
  printf 'version = 1\ndefault_agent = "main"\n\n[privacy]\nmode = "private"\n\n[[providers]]\nid = "fakey"\nbase_url = "http://127.0.0.1:%s/v1"\nmodel = "fake-model"\nkind = "openai-compat"\n\n[prices.models."fake-model"]\ninput_cents_per_million = 0\noutput_cents_per_million = 0\n' \
    "$(cat "$WORK/recorder.port")" >"$WORK/home/.auxesis/config.toml"
  (umask 077; printf 'AUX_KEY_FAKEY=fictional-key\n' >"$WORK/home/.auxesis/.env")
  # The client card matches the fixture mail and meeting by this second address
# (scripts/fixtures/hero-m2), and holds one E.164 phone.
  printf 'BEGIN:VCARD\nVERSION:3.0\nFN:%s\nEMAIL:%s\nEMAIL:%s\nTEL:%s\nEND:VCARD\n' "$NAME" "$EMAIL" "$CLIENT_EMAIL" "$CLIENT_PHONE" >"$WORK/contact.vcf"
  sbx "$AUX" contacts import "$WORK/contact.vcf" >"$WORK/import.log" 2>&1 || red "aux contacts import failed: $(cat "$WORK/import.log")"
}

step_start() {
  STEP="start"
  # TMPDIR under the run: the stdio child's mandatory sandbox gives it a
  # private aux-mcp-* temp dir below this, where the fixture writes its log.
  env -i HOME="$WORK/home" AUXESIS_HOME="$WORK/home/.auxesis" \
    AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 TMPDIR="$WORK/m6/tmp" \
    "$AUXD" >"$WORK/auxd.log" 2>&1 &
  AUXD_PID=$!
  local i
  for i in $(seq 1 150); do
    PORT="$(sed -n 's/.*auxd api on http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$WORK/auxd.log" | head -1)"
    [ -n "$PORT" ] && break
    kill -0 "$AUXD_PID" 2>/dev/null || red "auxd exited before listening: $(tail -n 3 "$WORK/auxd.log")"
    sleep 0.2
  done
  [ -n "$PORT" ] || red "auxd never announced its API port"
  TOKEN="$(tr -d '\n' < "$WORK/home/.auxesis/api.token")"
}

# One authenticated call. Sets HTTP_CODE; the body is in $WORK/resp.json.
api() {
  local method="$1" path="$2" data="${3:-}"
  local args=(--config - -sS -m 60 -X "$method" -o "$WORK/resp.json" -w '%{http_code}')
  if [ -n "$data" ]; then
    args+=(-H 'Content-Type: application/json' --data-binary "$data")
  fi
  # The bearer header goes to curl on stdin (`--config -`), never on its argv.
  HTTP_CODE="$(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" \
    | curl "${args[@]}" "http://127.0.0.1:$PORT$path")" || HTTP_CODE="000"
}

# A fresh install has the chief alone; the owner creates a
# domain agent from its template (POST /v1/agents {template}), as the app does.
from_template() {
  [ -d "$WORK/home/.auxesis/agents/$1" ] && return 0
  api POST /v1/agents "{\"template\":\"$1\"}"
  [ "$HTTP_CODE" = 201 ] || red "creating the $1 agent from its template returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
}

step_health() {
  STEP="health"
  api GET /v1/health
  [ "$HTTP_CODE" = 200 ] || red "GET /v1/health returned HTTP $HTTP_CODE"
  [ "$(jq -r '.ok' "$WORK/resp.json")" = "true" ] || red "/v1/health did not report ok"
}

step_turn() {
  STEP="turn"
  api POST /v1/threads/main/messages "$(jq -cn --arg c "$MESSAGE" '{content: $c}')"
  [ "$HTTP_CODE" = 200 ] || red "POST /v1/threads/main/messages returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  REPLY="$(jq -r '[.messages[] | select(.role == "assistant")] | last | .content // empty' "$WORK/resp.json")"
  [ -n "$REPLY" ] || red "the turn returned no assistant reply"
  case "$REPLY" in
    "[fake:fakey] "*) ;;
    *) red "reply is not from the fake provider: $(head -c 200 <<<"$REPLY")" ;;
  esac
}

step_privacy() {
  STEP="privacy"
  # Outbound: what left auxd, read by the recorder, holds tokens, never values.
  # A name is no hidden value: it reaches the provider as written.
  grep -qF "$NAME" "$WORK/provider-bodies.jsonl" || red "the name did not reach the provider as written"
  grep -qF "$EMAIL" "$WORK/provider-bodies.jsonl" && red "the raw e-mail address reached the provider"
  grep -qF "⟦" "$WORK/provider-bodies.jsonl" || red "no privacy token in what the provider received"
  # Display: the echoed tokens are shown to the owner restored, never raw.
  [[ "$REPLY" == *"$NAME"* && "$REPLY" == *"$EMAIL"* ]] || red "the reply was not restored for the owner"
  [[ "$REPLY" != *"⟦"* ]] || red "a raw privacy token was shown to the owner"
}

step_ledger() {
  STEP="ledger"
  api GET "/v1/receipts?agent=main"
  [ "$HTTP_CODE" = 200 ] || red "GET /v1/receipts returned HTTP $HTTP_CODE"
  # The turn's receipt: the agent's run, with provider tokens counted.
  jq -e 'any(.[]; .agent == "main" and .tokens_in > 0)' "$WORK/resp.json" >/dev/null ||
    red "the ledger has no receipt for the turn: $(head -c 300 "$WORK/resp.json")"
}

# RFC 3339 local instant for a day offset (+0d, +1d) and an HHMM time. macOS date(1).
local_instant() {
  date -v"$1" -v"${2:0:2}H" -v"${2:2:2}M" -v0S '+%Y-%m-%dT%H:%M:%S%z' |
    sed -E 's/([+-][0-9]{2})([0-9]{2})$/\1:\2/'
}

# Start the loopback simulator on a fictional mailbox stamped to today. It binds
# its own ephemeral ports and writes its CA into the sandbox temp dir.
step_m2_simulator() {
  STEP="m2-simulator"
  mkdir -p "$WORK/sim"
  local mailbox
  mailbox="$(cat "$FIXTURES/mailbox.json")"
  mailbox="${mailbox//@TODAY@/$(date '+%a, %d %b %Y %H:%M:%S %z')}"
  printf '%s\n' "$mailbox" >"$WORK/sim/mailbox.json"
  env -i HOME="$WORK/home" AUXESIS_HOME="$WORK/home/.auxesis" \
    AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 "$AUXFAKEMAIL" serve --dir "$WORK/sim" \
    --imap-port 0 --smtp-port 0 >"$WORK/fakemail.log" 2>&1 &
  FAKEMAIL_PID=$!
  local i line=""
  for i in $(seq 1 150); do
    line="$(sed -n 's/^fakemail imap=127\.0\.0\.1:\([0-9][0-9]*\) .*/\1/p' "$WORK/fakemail.log" | head -1)"
    [ -n "$line" ] && break
    kill -0 "$FAKEMAIL_PID" 2>/dev/null || red "aux-fakemail exited before listening: $(tail -n 3 "$WORK/fakemail.log")"
    sleep 0.2
  done
  [ -n "$line" ] || red "aux-fakemail never announced its IMAP port"
  IMAP_PORT="$line"
  CA_FILE="$WORK/sim/cert.pem"
  [ -s "$CA_FILE" ] || red "aux-fakemail wrote no CA file"
}

# Point the sandbox mail account at the simulator, the way the owner's auxd is
# configured: [connectors.mail] in config.toml, the password in the sandbox .env.
step_m2_config() {
  STEP="m2-config"
  local config="$WORK/home/.auxesis/config.toml"
  # The brief reads calendar and mail, which private mode refuses (privacy registry
  # row). Switch the mode only now, after the first privacy checks. The daemon reads
  # its config again on every call, so no restart is needed.
  sed 's/^mode = "private"$/mode = "open"/' "$config" >"$config.tmp" && mv "$config.tmp" "$config"
  grep -q '^mode = "open"$' "$config" || red "could not switch privacy to open for the brief"
  # Quiet hours: the brief skips inside [quiet] (default 22:00-07:00). An empty
  # window, start = end, is never quiet: aux-brief's in_quiet_hours needs
  # now >= start && now < end, which cannot hold when start == end. So the smoke
  # runs at any clock time.
  printf '\n[ui]\nlanguage = "en"\n\n[quiet]\nstart = "00:00"\nend = "00:00"\n\n[connectors.mail]\n\n[[connectors.mail.accounts]]\nid = "smokesim"\nemail = "owner@mailsim.test"\n\n[connectors.mail.accounts.imap]\nhost = "127.0.0.1"\nport = %s\nsecurity = "tls"\nca_file = "%s"\n' \
    "$IMAP_PORT" "$CA_FILE" >>"$config"
  # The simulator accepts any password. It lives in the sandbox .env, created
  # 0600 from the start (umask 077 in a subshell, no 0644 window), never the Keychain.
  (
    umask 077
    printf 'AUX_MAIL_SMOKESIM=fictional-password\n' >>"$WORK/home/.auxesis/.env"
  )
}

# Publish the fictional EventKit snapshot the way the Mac app does: over the
# bearer-authenticated loopback API (204 on success).
step_m2_calendar() {
  STEP="m2-calendar"
  local snapshot
  snapshot="$(cat "$FIXTURES/calendar.json")"
  snapshot="${snapshot//@TODAY_0930@/$(local_instant +0d 0930)}"
  snapshot="${snapshot//@TODAY_1000@/$(local_instant +0d 1000)}"
  snapshot="${snapshot//@TODAY_1400@/$(local_instant +0d 1400)}"
  snapshot="${snapshot//@TODAY_1500@/$(local_instant +0d 1500)}"
  snapshot="${snapshot//@TOMORROW_1000@/$(local_instant +1d 1000)}"
  snapshot="${snapshot//@TOMORROW_1100@/$(local_instant +1d 1100)}"
  # The app's capture facts: read now, from today's midnight out 8 days.
  snapshot="${snapshot//@NOW@/$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
  snapshot="${snapshot//@TODAY_0000@/$(local_instant +0d 0000)}"
  snapshot="${snapshot//@DAY8_0000@/$(local_instant +8d 0000)}"
  api POST /v1/apple-eventkit/snapshot "$snapshot"
  [ "$HTTP_CODE" = 204 ] || red "POST /v1/apple-eventkit/snapshot returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
}

step_m2_brief() {
  STEP="m2-brief"
  # A written brief is the CLI's stdout. The run also raises a counts-only
  # notification through the local macOS display; no sandbox sink captures it, so
  # this smoke does not inspect that text (crates/auxd/tests/local_brief.rs does).
  local brief again meetings
  brief="$(sbx_cli brief now 2>"$WORK/brief.err")" || red "aux brief now failed: $(head -c 300 "$WORK/brief.err")"
  [[ "$brief" == "Today "* ]] || red "the brief was not written: $(head -c 200 <<<"$brief")"
  meetings="$(grep -c '^• [0-9][0-9]:[0-9][0-9]' <<<"$brief" || true)"
  [ "$meetings" = "$EXPECT_MEETINGS" ] || red "brief lists $meetings meeting(s), expected $EXPECT_MEETINGS"
  [[ "$brief" == *"Call with Camille Exemple"* ]] || red "brief misses today's meeting with Camille Exemple"
  [[ "$brief" != *"Fictional retro tomorrow"* ]] || red "brief lists tomorrow's meeting"
  # Whole-line match: "13 unread" must not satisfy an expected 3. The wording is
  # BriefUnreadMany ("{0} unread"), not "{0} new message(s)".
  grep -qxF "$EXPECT_UNREAD unread" <<<"$brief" || red "brief does not count $EXPECT_UNREAD unread mail(s)"
  # Daily idempotency: a second run today answers already_today, not a second brief.
  again="$(sbx_cli brief now 2>"$WORK/brief2.err")" || red "second aux brief now failed: $(head -c 300 "$WORK/brief2.err")"
  [ "$again" = "$ALREADY_TODAY" ] || red "second run did not report already_today: $(head -c 200 <<<"$again")"
}

# The agent the CLI runs skills as: `main`, open mode (the brief step already
# switched the mode), the CRM tools, and the shipped log-interaction skill.
# `main` is the chief: its tool list caps every agent, so it
# also lists what the Calendar and Mail agents run in M4.
step_m3_skill_setup() {
  STEP="m3-skill-setup"
  local agent_dir="$WORK/home/.auxesis/agents/main"
  mkdir -p "$agent_dir/skills"
  printf -- '---\nname: main\nbrain: cloud\ndefault_mode: open\nchannels: [mac]\ntools:\n  - crm.search\n  - crm.get\n  - crm.log_interaction\n  - docs.ingest\n  - calendar.list_events\n  - calendar.create_event\n  - calendar.update_event\n  - reminders.list\n  - mail.list\n  - mail.search\n  - mail.thread\n  - mail.read\n  - mail.draft\n  - mail.send\n  - calendar_freebusy\n  - recall\n  - remember\n  - suggest_memory\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nHero smoke assistant.\n' \
    >"$agent_dir/agent.md"
  cp "$REPO_ROOT/crates/aux-runtime/src/skills/fixtures/skills/log-interaction.md" "$agent_dir/skills/log-interaction.md"
}

# Attach the fixture mail and meeting to the client the way the daemon's 30-minute
# job does: `aux crm timeline refresh` (same code path), exact address match.
step_m3_timeline() {
  STEP="m3-timeline"
  local out
  out="$(sbx_cli crm timeline refresh 2>"$WORK/refresh.err")" || red "aux crm timeline refresh failed: $(head -c 300 "$WORK/refresh.err")"
  [[ "$out" == "timeline refresh: "* ]] || red "unexpected refresh output: $(head -c 200 <<<"$out")"
}

# Open the card over the bearer-authenticated loopback API and keep it in resp.json.
open_card() {
  api GET /v1/clients
  [ "$HTTP_CODE" = 200 ] || red "GET /v1/clients returned HTTP $HTTP_CODE"
  CLIENT_ID="$(jq -r --arg n "$NAME" '[.[] | select(.display_name == $n)] | if length == 1 then .[0].id else empty end' "$WORK/resp.json")"
  [ -n "$CLIENT_ID" ] || red "no single client named $NAME in /v1/clients"
  api GET "/v1/clients/$CLIENT_ID"
  [ "$HTTP_CODE" = 200 ] || red "GET /v1/clients/$CLIENT_ID returned HTTP $HTTP_CODE"
}

step_m3_card() {
  STEP="m3-card"
  open_card
  jq -e --arg p "$CLIENT_PHONE" '.party.phones | index($p) != null' "$WORK/resp.json" >/dev/null ||
    red "the card does not hold the E.164 phone"
  jq -e --arg s "$MAIL_SUBJECT" 'any(.timeline[]; .kind == "mail" and (.summary | contains($s)))' "$WORK/resp.json" >/dev/null ||
    red "the timeline has no mail \"$MAIL_SUBJECT\": $(jq -c '[.timeline[] | {kind, summary}]' "$WORK/resp.json" | head -c 300)"
  jq -e --arg s "$MEETING_TITLE" 'any(.timeline[]; .kind == "meeting" and (.summary | contains($s)))' "$WORK/resp.json" >/dev/null ||
    red "the timeline has no meeting \"$MEETING_TITLE…\": $(jq -c '[.timeline[] | {kind, summary}]' "$WORK/resp.json" | head -c 300)"
}

# Log one interaction through the skill (each_run approval: the owner's `y` on
# stdin), then see it on the card with the skill's provenance.
step_m3_log() {
  STEP="m3-log"
  local out
  # The fill holds client data: hand it over in a sandbox file, never in argv.
  jq -cn --arg n "$NAME" --arg note "$LOG_NOTE" '{
    slots: {party: $n, note: $note},
    calls: [{tool: "crm_log_interaction", arguments: {
      party: $n, kind: "note", at: "2026-10-06T10:00:00Z",
      source_ref: "{\"owner\":true}", summary: $note,
      memory: [{kind: "fact", title: $note, body: "Rappeler la semaine prochaine."}]}}]}' >"$WORK/fill.json"
  out="$(printf 'y\n' | sbx_cli skill run log-interaction "@$WORK/fill.json" 2>"$WORK/skill.err")" || red "aux skill run log-interaction failed: $(head -c 300 "$WORK/skill.err") $(head -c 300 <<<"$out")"
  [[ "$out" == *"ran 1 action(s)"* ]] || red "log-interaction did not run its one action: $(head -c 300 <<<"$out")"
  open_card
  # Pinned text, not $LOG_NOTE: changing the logged note must break this step.
  jq -e --arg s "Appel de suivi fictif" 'any(.timeline[]; .kind == "note" and .provenance == "skill:log-interaction" and (.summary | contains($s)))' "$WORK/resp.json" >/dev/null ||
    red "the logged interaction is not on the card: $(jq -c '[.timeline[] | {kind, summary, provenance}]' "$WORK/resp.json" | head -c 300)"
  jq -e --arg s "Appel de suivi fictif" 'any(.memory[]; .title | contains($s))' "$WORK/resp.json" >/dev/null ||
    red "the logged memory item is not on the card"
}


# M4: the app side of the invite. A stdlib WebSocket client on /v1/events logs
# every frame type and answers the calendar bridge the way the Mac app does
# (POST /v1/bridge/{id}); no EventKit is touched.
step_m4_setup() {
  STEP="m4-setup"
  SMTP_PORT="$(sed -n 's/^fakemail imap=.* smtp=127\.0\.0\.1:\([0-9][0-9]*\) .*/\1/p' "$WORK/fakemail.log" | head -1)"
  [ -n "$SMTP_PORT" ] || red "aux-fakemail never announced its SMTP port"
  printf '\n[connectors.mail.accounts.smtp]\nhost = "127.0.0.1"\nport = %s\nsecurity = "tls"\nca_file = "%s"\n' \
    "$SMTP_PORT" "$CA_FILE" >>"$WORK/home/.auxesis/config.toml"
  # A demo-world client (aux-fakemail world.json): fictional, known to the contacts.
  printf 'BEGIN:VCARD\nVERSION:3.0\nFN:%s\nORG:Blueharbor\nEMAIL:%s\nTZ:America/New_York\nEND:VCARD\n' "$INVITEE" "$INVITEE_EMAIL" >"$WORK/invitee.vcf"
  sbx "$AUX" contacts import "$WORK/invitee.vcf" >"$WORK/import2.log" 2>&1 || red "aux contacts import failed: $(cat "$WORK/import2.log")"
  # The Calendar agent owns send-invite: made from its template, it gets its
  # shipped grants, agent.md and skill.
  from_template calendar
  local agent_dir="$WORK/home/.auxesis/agents/calendar"
  [ -f "$agent_dir/agent.md" ] || red "auxd did not install the Calendar agent.md"
  cmp -s "$agent_dir/skills/send-invite.md" "$REPO_ROOT/crates/aux-runtime/src/skills/fixtures/skills/send-invite.md" \
    || red "auxd did not install the shipped send-invite skill"
  cat >"$WORK/app.py" <<'PY'
import base64, json, os, socket, struct, sys, urllib.request
port, token, log = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
def note(line):
    with open(log, "a") as out: out.write(line + "\n")
s = socket.create_connection(("127.0.0.1", int(port)))
s.sendall(("GET /v1/events HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer %s\r\n\r\n"
           % (port, base64.b64encode(os.urandom(16)).decode(), token)).encode())
f = s.makefile("rb")
if b" 101 " not in f.readline(): sys.exit("no websocket upgrade")
while f.readline() not in (b"\r\n", b""): pass
note("connected")
def read(n):
    data = f.read(n)
    if len(data) < n: sys.exit(0)
    return data
def send(op, data):
    mask = os.urandom(4)
    s.sendall(bytes([0x80 | op, 0x80 | len(data)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))
events = 0
while True:
    b0, b1 = read(2)
    op, n = b0 & 0x0F, b1 & 0x7F
    n = struct.unpack(">H", read(2))[0] if n == 126 else struct.unpack(">Q", read(8))[0] if n == 127 else n
    data = read(n)
    if op == 8: sys.exit(0)
    if op == 9: send(0xA, data[:125]); continue
    if op != 1: continue
    frame = json.loads(data)
    note(str(frame.get("type")))
    if frame.get("type") == "bridge.request" and frame.get("op") == "eventkit.create_event":
        events += 1
        body = json.dumps({"ok": True, "result": {"event_id": "smoke-evt-%d" % events, "calendar": "Home"}}).encode()
        req = urllib.request.Request("http://127.0.0.1:%s/v1/bridge/%s" % (port, frame["id"]), data=body, method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
        urllib.request.urlopen(req, timeout=10).read()
PY
  python3 -I "$WORK/app.py" "$PORT" "$WORK/home/.auxesis/api.token" "$WORK/app.log" >"$WORK/app.err" 2>&1 &
  APP_PID=$!
  local i
  for i in $(seq 1 50); do grep -qx connected "$WORK/app.log" 2>/dev/null && break; sleep 0.1; done
  grep -qx connected "$WORK/app.log" 2>/dev/null || red "the fake app did not open /v1/events: $(head -c 200 "$WORK/app.err")"
}

# Start one turn in the background (default: /invite on calendar): it blocks
# on the approval card.
m4_turn() {
  local thread="${2:-calendar}" content="${3:-/invite $INVITEE tomorrow 10:00}"
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" |
    curl --config - -sS -m 120 -X POST -o "$WORK/$1.json" -w '%{http_code}' \
      -H 'Content-Type: application/json' --data-binary "$(jq -cn --arg c "$content" '{content: $c}')" \
      "http://127.0.0.1:$PORT/v1/threads/$thread/messages" >"$WORK/$1.code" 2>"$WORK/$1.err" &
  TURN_PID=$!
}

# Wait (30 s max) for the background turn to raise a card; set APPROVAL_ID.
m4_wait_card() {
  local i
  APPROVAL_ID=""
  for i in $(seq 1 150); do
    api GET "/v1/approvals?state=pending"
    [ "$HTTP_CODE" = 200 ] && [ "$(jq length "$WORK/resp.json")" -gt 0 ] && break
    kill -0 "$TURN_PID" 2>/dev/null || red "the turn ended without an approval: $(head -c 300 "$WORK/$1.json")"
    sleep 0.2
  done
  [ "$(jq length "$WORK/resp.json")" = 1 ] || red "expected 1 pending approval, got $(jq -c '[.[] | .headline]' "$WORK/resp.json" | head -c 300)"
  APPROVAL_ID="$(jq -r '.[0].id' "$WORK/resp.json")"
}

m4_end_turn() {
  wait "$TURN_PID" || true
  TURN_PID=""
  [ "$(cat "$WORK/$1.code")" = 200 ] || red "the $1 turn returned HTTP $(cat "$WORK/$1.code"): $(head -c 300 "$WORK/$1.json")"
}

outbox_count() {
  find "$WORK/sim/outbox" -name '*.eml' | wc -l | tr -d ' '
}

step_m4_invite() {
  STEP="m4-invite"
  local i sent check
  # 1. An approval appears in the app, and nothing reaches SMTP before the yes.
  m4_turn m4-deny
  m4_wait_card m4-deny
  grep -qx approval.new "$WORK/app.log" || red "the app was not told of the approval"
  [ "$(outbox_count)" = 0 ] || red "a mail was sent before any yes"
  echo "m4: pending=1 sent=0 before the answer"
  # 2. No: still nothing sent, nothing left pending.
  api POST "/v1/approvals/$APPROVAL_ID" '{"decision":"deny"}'
  [ "$HTTP_CODE" = 200 ] || red "deny returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  m4_end_turn m4-deny
  [ "$(outbox_count)" = 0 ] || red "a mail was sent after a no"
  api GET "/v1/approvals?state=pending"
  [ "$(jq length "$WORK/resp.json")" = 0 ] || red "an approval is still pending after the no"
  echo "m4: denied, sent=0"
  # Yes: exactly one mail, a text/calendar REQUEST part, to the client only.
  m4_turn m4-allow
  m4_wait_card m4-allow
  [ "$(outbox_count)" = 0 ] || red "a mail was sent before the yes"
  # "Slots proposed in the client's time zone" (PLAN.md). The invite is
  # written in Paris time and the fixture client is in New York: the card the
  # owner approves must show 10:00 Paris and her own start, a converted hour.
  jq -c '.[0]' "$WORK/resp.json" >"$WORK/invite-card.json"
  check="$(python3 -I - "$WORK/invite-card.json" <<'PY'
import json, sys
from datetime import datetime
from zoneinfo import ZoneInfo
card = json.load(open(sys.argv[1]))
calls = json.loads(card["edit_preview"])["calls"]
real = next(c["real"] for c in calls if c["tool"] == "apple_calendar_create_event")
start = datetime.fromisoformat(real["start"])
guest = start.astimezone(ZoneInfo(real["attendee_time_zone"])).isoformat()
shown = "apple_calendar_create_event. attendee_start: " + guest

def need(ok, why):
    if not ok:
        sys.exit(why)

need(real.get("time_zone") == "Europe/Paris", "the owner's zone is not on the card: %r" % (real.get("time_zone"),))
# CLIENT-TZ-FIELD: the model guessed Asia/Tokyo; the stored client-card
# America/New_York wins, and the card detail says so.
need(real.get("attendee_time_zone") == "America/New_York", "the client's stored zone did not win: %r" % (real.get("attendee_time_zone"),))
source = real.get("attendee_time_zone_source") or ""
need("client card" in source and "Asia/Tokyo" in source, "the card does not say the stored zone won: %r" % (source,))
need(start.strftime("%H:%M") == "10:00", "the wall time moved: %s" % start.isoformat())
need(real.get("attendee_start") == guest, "the client's start is %r, the converted hour is %r" % (real.get("attendee_start"), guest))
need(shown in card["detail"], "the card does not show the client's start: %r" % (card["detail"],))
print("owner=Europe/Paris guest_zone=America/New_York model_zone=Asia/Tokyo wall=10:00 guest_start=%s card=shown" % guest)
PY
)" || red "the invite card is not readable"
  [[ "$check" == owner=Europe/Paris\ guest_zone=America/New_York\ model_zone=Asia/Tokyo\ wall=10:00\ guest_start=*\ card=shown ]] ||
    red "the invite does not propose the client's time zone: $check"
  echo "m4: invite $check"
  api POST "/v1/approvals/$APPROVAL_ID" '{"decision":"allow_once"}'
  [ "$HTTP_CODE" = 200 ] || red "allow_once returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  m4_end_turn m4-allow
  for i in $(seq 1 50); do [ "$(outbox_count)" -gt 0 ] && break; sleep 0.2; done
  sent="$(outbox_count)"
  [ "$sent" = 1 ] || red "expected 1 mail after the yes, got $sent"
  api GET "/v1/approvals?state=pending"
  [ "$(jq length "$WORK/resp.json")" = 0 ] || red "a second approval was asked after the yes"
  check="$(python3 -I - "$(find "$WORK/sim/outbox" -name '*.eml')" "$INVITEE_EMAIL" "$WORK/invite-card.json" <<'PY'
import email, email.policy, email.utils, json, sys
from datetime import datetime, timezone
mail = email.message_from_binary_file(open(sys.argv[1], "rb"), policy=email.policy.default)
rcpt = [a for _, a in email.utils.getaddresses(mail.get_all("To", []) + mail.get_all("Cc", []) + mail.get_all("Bcc", []))]
cal = [p for p in mail.walk() if p.get_content_type() == "text/calendar"]
ics = cal[0].get_content().replace("\r\n ", "") if len(cal) == 1 else ""
card = json.load(open(sys.argv[3]))
calls = json.loads(card["edit_preview"])["calls"]
real = next(c["real"] for c in calls if c["tool"] == "apple_calendar_create_event")
# The .ics carries UTC instants; this one must be the client's own start
# (America/New_York), the hour the card proposed, not the owner's 10:00.
guest_utc = datetime.fromisoformat(real["attendee_start"]).astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
print("rcpt=%s calendar_parts=%d method_request=%s attendee=%s dtstart_client=%s" % (",".join(rcpt), len(cal),
      "METHOD:REQUEST" in ics.splitlines(), ("mailto:" + sys.argv[2]).lower() in ics.lower(),
      ("DTSTART:" + guest_utc) in ics.splitlines()))
PY
)"
  echo "m4: $check"
  [ "$check" = "rcpt=$INVITEE_EMAIL calendar_parts=1 method_request=True attendee=True dtstart_client=True" ] || red "the invite mail is wrong: $check"
  # 3. A repeat yes on the same id sends nothing more.
  api POST "/v1/approvals/$APPROVAL_ID" '{"decision":"allow_once"}'
  [ "$HTTP_CODE" = 404 ] || red "a repeat yes on $APPROVAL_ID gave HTTP $HTTP_CODE, expected 404 (200 = accepted twice; 5xx or 000 = crash)"
  sleep 1
  [ "$(outbox_count)" = 1 ] || red "a repeat yes sent a second mail"
  echo "m4: repeat yes HTTP $HTTP_CODE, sent=1"
}

# M4-3a: /followup on the Mail agent. One card; no sends nothing; yes sends
# exactly the card's To/Subject/Body, to the contact's own address.
step_m4_followup() {
  STEP="m4-followup"
  local agent_dir="$WORK/home/.auxesis/agents/mail" before i check
  from_template mail
  cmp -s "$agent_dir/skills/follow-up.md" "$REPO_ROOT/crates/auxd/src/agents/mail/skills/follow-up.md" \
    || red "auxd did not install the shipped follow-up skill"
  before="$(outbox_count)"
  m4_turn m4-fu-deny mail "/followup $INVITEE"
  m4_wait_card m4-fu-deny
  grep -q 'pre_read_0_search' "$WORK/provider-bodies.jsonl" || red "/followup did not read the last exchange first"
  api POST "/v1/approvals/$APPROVAL_ID" '{"decision":"deny"}'
  [ "$HTTP_CODE" = 200 ] || red "deny returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  m4_end_turn m4-fu-deny
  [ "$(outbox_count)" = "$before" ] || red "a follow-up was sent after a no"
  m4_turn m4-fu-allow mail "/followup $INVITEE"
  m4_wait_card m4-fu-allow
  jq '.[0]' "$WORK/resp.json" >"$WORK/fu-card.json"
  [ "$(outbox_count)" = "$before" ] || red "a follow-up was sent before the yes"
  api POST "/v1/approvals/$APPROVAL_ID" '{"decision":"allow_once"}'
  [ "$HTTP_CODE" = 200 ] || red "allow_once returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  m4_end_turn m4-fu-allow
  for i in $(seq 1 50); do [ "$(outbox_count)" -gt "$before" ] && break; sleep 0.2; done
  [ "$(outbox_count)" = $((before + 1)) ] || red "expected 1 follow-up after the yes, got $(( $(outbox_count) - before ))"
  check="$(python3 -I - "$(find "$WORK/sim/outbox" -name '*.eml' -newer "$WORK/fu-card.json")" "$WORK/fu-card.json" <<'PY'
import email, email.policy, email.utils, json, sys
mail = email.message_from_binary_file(open(sys.argv[1], "rb"), policy=email.policy.default)
# The card is the text the owner reads (preview) plus the exact
# arguments (edit_preview); the mail must be both.
card = json.load(open(sys.argv[2]))
real = json.loads(card["edit_preview"])["calls"][0]["real"]
rcpt = [a for _, a in email.utils.getaddresses(mail.get_all("To", []) + mail.get_all("Cc", []) + mail.get_all("Bcc", []))]
body = mail.get_body(("plain",)).get_content().strip()
print("rcpt=%s card_to=%s same_subject=%s same_body=%s shown=%s" % (",".join(rcpt), ",".join(real["to"]),
      mail["Subject"] == real["subject"], body == real["body"].strip(), body in card["preview"]))
PY
)"
  echo "m4: followup $check"
  [ "$check" = "rcpt=$INVITEE_EMAIL card_to=$INVITEE_EMAIL same_subject=True same_body=True shown=True" ] || red "the follow-up mail is not the card: $check"
}

# /availability. No sends nothing; yes sends the card's mail, whose
# times are the runtime's (one line per window, in the owner's zone).
step_m4_availability() {
  STEP="m4-availability"
  local before check
  before="$(outbox_count)"
  m4_turn m4-av-deny mail "/availability $INVITEE"
  m4_wait_card m4-av-deny
  api POST "/v1/approvals/$APPROVAL_ID" '{"decision":"deny"}'
  [ "$HTTP_CODE" = 200 ] || red "deny returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  m4_end_turn m4-av-deny
  [ "$(outbox_count)" = "$before" ] || red "free times were sent after a no"
  m4_turn m4-av-allow mail "/availability $INVITEE"
  m4_wait_card m4-av-allow
  jq '.[0]' "$WORK/resp.json" >"$WORK/av-card.json"
  api POST "/v1/approvals/$APPROVAL_ID" '{"decision":"allow_once"}'
  [ "$HTTP_CODE" = 200 ] || red "allow_once returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  m4_end_turn m4-av-allow
  for _ in $(seq 1 50); do [ "$(outbox_count)" -gt "$before" ] && break; sleep 0.2; done
  [ "$(outbox_count)" = $((before + 1)) ] || red "expected 1 free-times mail after the yes, got $(( $(outbox_count) - before ))"
  check="$(python3 -I - "$(find "$WORK/sim/outbox" -name '*.eml' -newer "$WORK/av-card.json")" "$WORK/av-card.json" <<'PY'
import email, email.policy, json, re, sys
mail = email.message_from_binary_file(open(sys.argv[1], "rb"), policy=email.policy.default)
card = json.load(open(sys.argv[2]))
real = json.loads(card["edit_preview"])["calls"][0]["real"]
# SMTP carries CRLF line ends, the card body LF.
body = mail.get_body(("plain",)).get_content().replace("\r\n", "\n").strip()
times = [l for l in body.splitlines() if re.match(r"^- \w{3} \d+ \w{3}, \d\d:\d\d–\d\d:\d\d \(", l)]
print("same_body=%s shown=%s marker=%s windows=%s" % (body == real["body"].strip(), body in card["preview"],
      "{free_times}" in body, "yes" if times else "none"))
PY
)"
  echo "m4: availability $check"
  [ "$check" = "same_body=True shown=True marker=False windows=yes" ] || red "the free-times mail is not the card: $check"
}

# The receipt mail (fixture uid 5: a PDF from the demo-world client Lea
# Blueharbor) is collected by the shipped collect-receipts skill, read by a fake
# bridge (the Mac app's PDFKit post), listed linked to that client, and
# exported. The four text-only mails are no documents; a second collect adds no row.
step_m5_collect() {
  STEP="m5-collect"
  local agent_dir="$WORK/home/.auxesis/agents/main" out run
  cp "$REPO_ROOT/crates/aux-runtime/src/skills/fixtures/skills/collect-receipts.md" "$agent_dir/skills/collect-receipts.md"
  jq -cn '{slots: {}, calls: [{tool: "docs_ingest", arguments: {account: "smokesim", days: 30}}]}' >"$WORK/collect.json"
  for run in 1 2; do
    out="$(printf 'y\n' | sbx_cli skill run collect-receipts "@$WORK/collect.json" 2>"$WORK/collect.err")" ||
      red "collect run $run failed: $(head -c 300 "$WORK/collect.err") $(head -c 300 <<<"$out")"
    [[ "$out" == *"ran 1 action(s)"* ]] || red "collect run $run did not run its one action: $(head -c 300 <<<"$out")"
  done
  echo "m5: collect-receipts ran twice"
}

# The Mac app's part: claim the PDF, read its bytes, post its text back.
step_m5_read() {
  STEP="m5-read"
  local hash
  api GET /v1/docs/extract/pending
  [ "$HTTP_CODE" = 200 ] || red "GET /v1/docs/extract/pending returned HTTP $HTTP_CODE"
  [ "$(jq -c '[.[] | .mime]' "$WORK/resp.json")" = '["application/pdf"]' ] ||
    red "expected 1 pending PDF, got $(head -c 300 "$WORK/resp.json")"
  hash="$(jq -r '.[0].hash' "$WORK/resp.json")"
  api GET "/v1/docs/$hash/blob"
  [ "$HTTP_CODE" = 200 ] || red "GET the claimed PDF returned HTTP $HTTP_CODE"
  [ "$(head -c 5 "$WORK/resp.json")" = "%PDF-" ] || red "the claimed blob is not the mailed PDF"
  api POST "/v1/docs/$hash/extraction" "$(jq -cn --arg d "$(date '+%Y-%m-%d')" --arg n "$INVITEE" \
    '{extractor: "pdf_text", pages: 1, text: ($n + "\nReceipt # BH-2026-0017\nIssued " + $d + "\nSubtotal 100.00 EUR\nVAT 20.00\nTotal due 120.00\n")}')"
  [ "$HTTP_CODE" = 200 ] || red "POST extraction returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
}

step_m5_list() {
  STEP="m5-list"
  local list lea
  api GET /v1/clients
  lea="$(jq -r --arg n "$INVITEE" '[.[] | select(.display_name == $n)] | if length == 1 then .[0].id else empty end' "$WORK/resp.json")"
  [ -n "$lea" ] || red "no single client named $INVITEE"
  list="$(sbx_cli docs list 2>"$WORK/list.err")" || red "aux docs list failed: $(head -c 300 "$WORK/list.err")"
  echo "m5: $list"
  [ "$(wc -l <<<"$list" | tr -d ' ')" = 1 ] || red "expected 1 document, got: $(head -c 300 <<<"$list")"
  [[ "$list" == *"BH-2026-0017"*"120.00 EUR"*"client $lea $INVITEE"*"[read]"* ]] || red "the receipt is not read and linked to client $lea"
}

step_m5_export() {
  STEP="m5-export"
  local out today folder
  today="$(date '+%Y-%m-%d')"
  mkdir "$WORK/export"
  out="$(sbx_cli docs export --from "$today" --to "$today" --out "$WORK/export" 2>"$WORK/export.err")" ||
    red "aux docs export failed: $(head -c 300 "$WORK/export.err")"
  echo "m5: $out"
  folder="$WORK/export/auxesis-receipts-$today-$today"
  [[ "$out" == "Exported 1 receipt(s) to "* ]] || red "unexpected export output: $(head -c 300 <<<"$out")"
  grep -q "BH-2026-0017.*$INVITEE" "$folder/receipts.csv" || red "receipts.csv has no linked row: $(head -c 300 "$folder/receipts.csv")"
  [ "$(find "$folder/originals" -type f | wc -l | tr -d ' ')" = 1 ] || red "expected 1 original in the export"
  grep -q '^%PDF-1.4 fictional receipt BH-2026-0017' "$folder/originals/"* || red "the exported original is not the mailed PDF"
  # An empty period is a clear message and exit 0, with nothing written.
  out="$(sbx_cli docs export --from 2001-01-01 --to 2001-01-31 --out "$WORK/export" 2>"$WORK/export2.err")" ||
    red "an empty export failed: $(head -c 300 "$WORK/export2.err")"
  echo "m5: empty period: $out"
  [ ! -e "$WORK/export/auxesis-receipts-2001-01-01-2001-01-31" ] || red "an empty period wrote a folder"
}

# The MCP stage starts from the open mode the brief stage set. Private mode is what tokenises MCP
# arguments (B14), so switch back and wait for the one watch rebuild before the
# server is approved. The added (disabled) server keeps the runtime non-empty,
# so the rebuild logs "MCP runtime started"; an empty runtime logs nothing.
step_m6_setup() {
  STEP="m6-setup"
  local config="$WORK/home/.auxesis/config.toml"
  local agent_dir="$WORK/home/.auxesis/agents/$M6_AGENT"
  local before now i
  before="$(grep -c 'MCP runtime started' "$WORK/auxd.log" || true)"
  sed 's/^mode = "open"$/mode = "private"/' "$config" >"$config.tmp" && mv "$config.tmp" "$config"
  grep -q '^mode = "private"$' "$config" || red "could not switch privacy to private for M6"
  for i in $(seq 1 100); do
    now="$(grep -c 'MCP runtime started' "$WORK/auxd.log" || true)"
    [ "$now" -gt "$before" ] && break
    kill -0 "$AUXD_PID" 2>/dev/null || red "auxd exited while switching to private"
    sleep 0.1
  done
  [ "$now" -gt "$before" ] || red "the MCP runtime did not rebuild for private mode"
  # The seeded `clients` agent carries the chat turn: an ad-hoc `main` has no
  # registry grants, and the grant ceiling refuses the mcp scope before the
  # broker sees the owner's exact allow rule. The overlay grants only mcp; the
  # rule is exact (MCP tools never ride a wildcard).
  mkdir -p "$agent_dir"
  printf '[[do]]\nskill = "mcp"\nlevel = "auto"\n' >"$agent_dir/grants.toml"
  # The chief caps every agent: it must cover the MCP bucket
  # and list both fixture tools too. M6 is the last step, so the chief's
  # overlay here changes no earlier one.
  local chief_dir="$WORK/home/.auxesis/agents/main"
  printf '[[do]]\nskill = "mcp"\nlevel = "auto"\n' >"$chief_dir/grants.toml"
  sed "s|^  - docs.ingest\$|  - docs.ingest\\
  - mcp__${M6_SERVER}__${M6_READ}\\
  - mcp__${M6_SERVER}__${M6_WRITE}|" "$chief_dir/agent.md" >"$chief_dir/agent.md.tmp" && mv "$chief_dir/agent.md.tmp" "$chief_dir/agent.md"
  grep -q "mcp__${M6_SERVER}__${M6_WRITE}" "$chief_dir/agent.md" || red "could not list the M6 tools for the chief"
  printf '\n[[rules]]\nagent = "%s"\ntool = "mcp__%s__%s"\naction = "allow"\n' \
    "$M6_AGENT" "$M6_SERVER" "$M6_READ" >>"$config"
}

step_m6_add() {
  STEP="m6-add"
  local body state
  body="$(jq -cn --arg cmd "$REPO_ROOT/scripts/fixtures/m6/mcp-fixture.sh" \
    --arg read "$M6_READ" --arg agent "$M6_AGENT" '{id: "m6notes", transport: "stdio", command: $cmd, agent: $agent, tools: [$read], data_class: "public"}')"
  api POST /v1/mcp/servers "$body"
  [ "$HTTP_CODE" = 200 ] || red "POST /v1/mcp/servers returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  M6_HASH="$(jq -r '.hash // empty' "$WORK/resp.json")"
  [ "${#M6_HASH}" = 64 ] || red "the install preview returned no 64-character hash"
  [ "$(jq -r '.enabled' "$WORK/resp.json")" = false ] || red "the added server is enabled before any approval"
  [ "$(find "$WORK/m6/tmp" -type f \( -name 'm6-pid' -o -name 'm6-calls.log' \) | wc -l | tr -d ' ')" = 0 ] ||
    red "an MCP child spawned before approval"
  api GET /v1/mcp/servers
  [ "$HTTP_CODE" = 200 ] || red "GET /v1/mcp/servers returned HTTP $HTTP_CODE"
  state="$(jq -r --arg id "$M6_SERVER" '.servers[] | select(.id == $id) | .state' "$WORK/resp.json")"
  [ "$state" = "disabled" ] || red "the added server is $state, expected disabled"
  echo "m6: installed disabled, hash ${M6_HASH:0:12}…, 0 children"
}

m6_wait_ready() {
  local i state
  for i in $(seq 1 150); do
    api GET /v1/mcp/servers
    [ "$HTTP_CODE" = 200 ] || red "GET /v1/mcp/servers returned HTTP $HTTP_CODE"
    state="$(jq -r --arg id "$M6_SERVER" '.servers[] | select(.id == $id) | .state' "$WORK/resp.json")"
    [ "$state" = "ready" ] && return 0
    kill -0 "$AUXD_PID" 2>/dev/null || red "auxd exited while waiting for $M6_SERVER"
    sleep 0.1
  done
  red "MCP server $M6_SERVER stayed $state, expected ready"
}

step_m6_approve() {
  STEP="m6-approve"
  api POST "/v1/mcp/servers/$M6_SERVER/approve" "$(jq -cn --arg h "$M6_HASH" --arg a "$M6_AGENT" '{hash: $h, agent: $a}')"
  [ "$HTTP_CODE" = 200 ] || red "approve returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  m6_wait_ready
  api GET /v1/mcp/servers
  # `tools` is the server's discovery list (both tools exist in the child);
  # `agents[$M6_AGENT]` is the allowlist that decides what the chat may mount.
  jq -e --arg id "$M6_SERVER" --arg agent "$M6_AGENT" --arg read "$M6_READ" \
    '(.servers[] | select(.id == $id)) as $s | $s.enabled and $s.state == "ready" and ($s.agents[$agent] == [$read])' \
    "$WORK/resp.json" >/dev/null || red "the approved server did not allow only $M6_READ: $(head -c 300 "$WORK/resp.json")"
  echo "m6: one yes started the child, $M6_READ only for $M6_AGENT"
}

step_m6_call() {
  STEP="m6-call"
  local log i
  api POST /v1/threads/$M6_AGENT/messages "$(jq -cn --arg c "$M6_MESSAGE" '{content: $c}')"
  [ "$HTTP_CODE" = 200 ] || red "the M6 chat turn returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  for i in $(seq 1 100); do
    log="$(find "$WORK/m6/tmp" -name m6-calls.log -type f | head -1)"
    [ -n "$log" ] && break
    sleep 0.1
  done
  [ -n "$log" ] || red "the MCP child saw no tools/call"
  grep -qF "READ_NOTE" "$log" || red "the child's call log does not name $M6_READ: $(head -c 300 "$log")"
  grep -qF "⟦IBAN_" "$log" || red "the child did not receive the IBAN token: $(head -c 300 "$log")"
  if grep -qF "$M6_IBAN" "$log" || grep -qF "$M6_IBAN_DIGITS" "$log"; then
    red "the raw IBAN reached the MCP child: $(head -c 300 "$log")"
  fi
  if grep -qF "$M6_IBAN" "$WORK/provider-bodies.jsonl" || grep -qF "$M6_IBAN_DIGITS" "$WORK/provider-bodies.jsonl"; then
    red "the raw IBAN reached the provider"
  fi
  grep -qF "⟦IBAN_" "$WORK/provider-bodies.jsonl" || red "the provider saw no IBAN token"
  echo "m6: child saw ⟦IBAN_…⟧, raw IBAN absent from child log and provider"
}

step_m6_widen() {
  STEP="m6-widen"
  local state
  api PUT "/v1/mcp/servers/$M6_SERVER/agents/$M6_AGENT" \
    "$(jq -cn --arg read "$M6_READ" --arg write "$M6_WRITE" '{tools: [$read, $write]}')"
  [ "$HTTP_CODE" = 409 ] || red "widening returned HTTP $HTTP_CODE, expected 409: $(head -c 300 "$WORK/resp.json")"
  grep -qF "approval_required" "$WORK/resp.json" || red "widening did not return approval_required: $(head -c 300 "$WORK/resp.json")"
  api GET /v1/mcp/servers
  state="$(jq -r --arg id "$M6_SERVER" '.servers[] | select(.id == $id) | .state' "$WORK/resp.json")"
  [ "$state" = "needs_approval" ] || red "the widened server is $state, expected needs_approval"
  jq -e --arg id "$M6_SERVER" --arg agent "$M6_AGENT" --arg read "$M6_READ" --arg write "$M6_WRITE" \
    '(.servers[] | select(.id == $id)) as $s | ($s.reason == "approval_required") and (($s.tools | length) == 0) and (($s.agents[$agent] | sort) == [$read, $write])' \
    "$WORK/resp.json" >/dev/null || red "a widened tool mounted before the second yes: $(head -c 300 "$WORK/resp.json")"
  api GET "/v1/mcp/servers/$M6_SERVER/approval"
  [ "$HTTP_CODE" = 200 ] || red "GET the new approval preview returned HTTP $HTTP_CODE"
  M6_HASH2="$(jq -r '.hash // empty' "$WORK/resp.json")"
  [ "${#M6_HASH2}" = 64 ] || red "the widened preview returned no 64-character hash"
  jq -e --arg read "$M6_READ" --arg write "$M6_WRITE" '(.tools | map(.name) | sort) == [$read, $write]' \
    "$WORK/resp.json" >/dev/null || red "the widened preview does not list both tools: $(head -c 300 "$WORK/resp.json")"
  echo "m6: growth refused 409 approval_required, $M6_WRITE not mounted, new hash ${M6_HASH2:0:12}…"
}

step_m6_reapprove() {
  STEP="m6-reapprove"
  api POST "/v1/mcp/servers/$M6_SERVER/approve" "$(jq -cn --arg h "$M6_HASH2" --arg a "$M6_AGENT" '{hash: $h, agent: $a}')"
  [ "$HTTP_CODE" = 200 ] || red "the second approve returned HTTP $HTTP_CODE: $(head -c 300 "$WORK/resp.json")"
  m6_wait_ready
  api GET /v1/mcp/servers
  jq -e --arg id "$M6_SERVER" --arg agent "$M6_AGENT" --arg read "$M6_READ" --arg write "$M6_WRITE" \
    '(.servers[] | select(.id == $id)) as $s | $s.enabled and $s.state == "ready" and (($s.tools | map(.name) | sort) == [$read, $write]) and (($s.agents[$agent] | sort) == [$read, $write])' \
    "$WORK/resp.json" >/dev/null || red "the second yes did not mount both tools: $(head -c 300 "$WORK/resp.json")"
  echo "m6: second yes mounted $M6_READ and $M6_WRITE"
}

step_build
# The 5 minute budget is the run, not the compile.
SECONDS=0
step_sandbox
step_start
step_health
step_turn
step_privacy
step_ledger
step_m2_simulator
step_m2_config
step_m2_calendar
step_m2_brief
step_m3_skill_setup
step_m3_timeline
step_m3_card
step_m3_log
M4_START=$SECONDS
step_m4_setup
step_m4_invite
step_m4_followup
step_m4_availability
M4_TIME=$((SECONDS - M4_START))
M5_START=$SECONDS
step_m5_collect
step_m5_read
step_m5_list
step_m5_export
M5_TIME=$((SECONDS - M5_START))
M6_START=$SECONDS
step_m6_add
step_m6_setup
step_m6_approve
step_m6_call
step_m6_widen
step_m6_reapprove
M6_TIME=$((SECONDS - M6_START))

ELAPSED=$SECONDS
[ "$ELAPSED" -lt 300 ] || red "over the 5 minute budget (${ELAPSED}s)"
echo "GREEN hero-smoke in ${ELAPSED}s: turn answered, receipt recorded, e-mail tokenised before the provider, name as written; brief built from $EXPECT_MEETINGS meetings and $EXPECT_UNREAD unread mails, already_today on the second run. M3 OK: client card shows 1 mail and 1 meeting on its timeline, 1 interaction logged through log-interaction. M4 OK in ${M4_TIME}s: 1 approval before the yes, 0 sent on no, 1 .ics REQUEST to the client on yes, none on a repeat yes, the card showed the client's own start (America/New_York) for a Paris invite; /followup sent the card's mail after 1 no and 1 yes; /availability sent the card's free times after 1 no and 1 yes. M5 OK in ${M5_TIME}s: 1 mailed receipt collected (twice, 1 row), read, linked to $INVITEE, exported to CSV + original. M6 OK in ${M6_TIME}s: fixture MCP installed disabled, one approval started it, the child saw ⟦IBAN_…⟧ and never the raw IBAN, a widened tool list returned 409 approval_required with no tool mounted, the second yes mounted $M6_READ and $M6_WRITE"
