#!/usr/bin/env bash
# End-to-end scenarios: a real, sandboxed auxd answers the owner's turns and
# the answers are checked with deterministic rules.
#
#   scripts/e2e/run.sh [--provider fake|cloud] [--only NAME]
#
# The fake provider is a local loopback recorder (scripts/e2e/toolkit.py); the cloud one reads its settings from the file the caller names in
# AUX_E2E_CLOUD_ENV (the provider block, then the keys). The world is the fictional demo one: no real contact, mail or key is read, the sandbox home
# is a fresh mktemp dir and the trap deletes it. Every auxd, aux and aux-fakemail call runs with a literal sandbox env (HOME and AUXESIS_HOME under
# the temp dir, AUXESIS_SANDBOX=1, AUXESIS_API_PORT=0).
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/lib/guard.sh
source "$REPO_ROOT/scripts/lib/guard.sh"
TOOLKIT="$REPO_ROOT/scripts/e2e/toolkit.py"
SCENARIOS="$REPO_ROOT/scripts/e2e/scenarios"
USAGE="usage: $0 [--provider fake|cloud] [--only NAME]"
PROVIDER="fake"
ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --provider) PROVIDER="${2:-}"; shift 2 ;;
        --only) ONLY="${2:-}"; shift 2 ;;
        -h | --help) sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "$USAGE" >&2; exit 2 ;;
    esac
done
case "$PROVIDER" in fake | cloud) ;; *) echo "$USAGE" >&2; exit 2 ;; esac

WORK="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-e2e.XXXXXX")"
HOME_DIR="$WORK/home"
AUX_HOME="$HOME_DIR/.auxesis"
SIM_DIR="$WORK/sim"
BODIES="$WORK/provider-bodies.jsonl"
TOKEN=""; PORT=""; IMAP_PORT=""; SMTP_PORT=""; CA_FILE=""; HTTP_CODE=""
AUXD_PID=""; FAKEMAIL_PID=""; RECORDER_PID=""; TURN_PID=""

red() { echo "e2e: RED $*" >&2; exit 1; }
cleanup() {
    kill "$TURN_PID" "$AUXD_PID" "$FAKEMAIL_PID" "$RECORDER_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# The sandbox every Auxesis binary runs under (the literal form the project mandates): `env -i` drops the real HOME too.
sbx() { env -i HOME="$HOME_DIR" AUXESIS_HOME="$AUX_HOME" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 "$@"; }
# The same in the background: `$!` is then the binary itself (env execs it), so the trap kills it. `sbx ... &` would fork a
# subshell, `$!` would be that subshell, and auxd and aux-fakemail outlived every run.
sbx_bg() { env -i HOME="$HOME_DIR" AUXESIS_HOME="$AUX_HOME" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 "$@" & }
# The same, with the loopback port auxd announced (the guard refuses port 0).
sbx_cli() { env -i HOME="$HOME_DIR" AUXESIS_HOME="$AUX_HOME" AUXESIS_SANDBOX=1 AUXESIS_API_PORT="$PORT" "$@"; }

AUXD="${AUXD:-$REPO_ROOT/target/release/auxd}"
AUX="${AUX:-$REPO_ROOT/target/release/aux}"
AUXFAKEMAIL="${AUXFAKEMAIL:-$REPO_ROOT/target/release/aux-fakemail}"
[ -x "$AUXD" ] || red "no auxd (set AUXD=<path>)"
[ -x "$AUX" ] || red "no aux (set AUX=<path>)"
[ -x "$AUXFAKEMAIL" ] || red "no aux-fakemail (set AUXFAKEMAIL=<path>)"
mkdir -p "$AUX_HOME" "$SIM_DIR"
umask 077
: >"$BODIES"

# The provider: the fake one is a loopback recorder, the cloud one is named by the caller (never read from a fixed path).
provider_block() {
    if [ "$PROVIDER" = fake ]; then
        python3 -I "$TOOLKIT" recorder "$BODIES" >"$WORK/recorder.log" 2>&1 &
        RECORDER_PID=$!
        recorder_port="$(wait_for "$WORK/recorder.log" 's/^recorder on 127\.0\.0\.1:\([0-9]*\)$/\1/p')" || red "the provider recorder did not start: $(tail -n 2 "$WORK/recorder.log")"
        printf '[[providers]]\nid = "fakey"\nkind = "openai-compat"\nbase_url = "http://127.0.0.1:%s/v1"\nmodel = "fake-model"\n' \
            "$recorder_port" >"$WORK/provider.toml"
        printf 'AUX_KEY_FAKEY=fictional-key\n' >"$AUX_HOME/.env"
    else
        [ -n "${AUX_E2E_CLOUD_ENV:-}" ] || red "--provider cloud needs AUX_E2E_CLOUD_ENV=<file>"
        [ -r "$AUX_E2E_CLOUD_ENV" ] || red "the file named by AUX_E2E_CLOUD_ENV cannot be read"
        # The provider block (TOML) first, then the keys: the values are
        # copied, never printed, and the keys land in the sandbox .env (0600).
        sed -n '/^[A-Za-z_][A-Za-z0-9_]*=/,$p' "$AUX_E2E_CLOUD_ENV" >"$WORK/cloud.env"
        sed '/^[A-Za-z_][A-Za-z0-9_]*=/,$d' "$AUX_E2E_CLOUD_ENV" >"$WORK/provider.toml"
        grep -q '^id = ' "$WORK/provider.toml" || red "the file named by AUX_E2E_CLOUD_ENV has no provider block"
        cp "$WORK/cloud.env" "$AUX_HOME/.env"
    fi
    # The local simulator takes any password for the owner's mailbox.
    printf 'AUX_MAIL_E2ESIM=fictional-password\n' >>"$AUX_HOME/.env"
    chmod 600 "$AUX_HOME/.env"
}

# The config: the provider, the privacy mode (the daemon reads it on every call), the language and the mail account of the simulator.
write_config() {
    printf 'version = 1\ndefault_agent = "main"\n\n[privacy]\nmode = "%s"\n\n[ui]\nlanguage = "en"\n\n[quiet]\nstart = "00:00"\nend = "00:00"\n\n%s\n[connectors.mail]\n\n[[connectors.mail.accounts]]\nid = "e2esim"\nemail = "owner@mailsim.test"\n\n[connectors.mail.accounts.imap]\nhost = "127.0.0.1"\nport = %s\nsecurity = "tls"\nca_file = "%s"\n\n[connectors.mail.accounts.smtp]\nhost = "127.0.0.1"\nport = %s\nsecurity = "tls"\nca_file = "%s"\n' \
        "$1" "$(cat "$WORK/provider.toml")" "$IMAP_PORT" "$CA_FILE" "$SMTP_PORT" "$CA_FILE" >"$AUX_HOME/config.toml"
}

# The two agents: the one that reads the world, and the calendar one that owns the invite skill (the only one that can send).
write_agents() {
    local dir="$AUX_HOME/agents"
    mkdir -p "$dir/main/skills" "$dir/calendar/skills"
    printf -- '---\nname: main\nbrain: cloud\ndefault_mode: open\nchannels: [mac]\ntools:\n  - mail.list\n  - mail.search\n  - mail.thread\n  - mail.read\n  - calendar.list_events\n  - reminders.list\n  - crm.search\n  - crm.get\n  - crm.list\n  - crm.today\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nE2E assistant.\n' >"$dir/main/agent.md"
    printf -- '---\nname: calendar\nbrain: cloud\ndefault_mode: open\nchannels: [mac]\ntools:\n  - calendar.list_events\n  - calendar.create_event\n  - reminders.list\n  - mail.send\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nE2E calendar assistant.\n' >"$dir/calendar/agent.md"
    cp "$REPO_ROOT/crates/aux-runtime/src/skills/fixtures/skills/send-invite.md" "$dir/calendar/skills/send-invite.md"
}

# One authenticated call: the bearer header goes to curl on stdin, never on its argv. Sets HTTP_CODE; the body lands in $WORK/resp.json.
api() {
    local method="$1" path="$2" data="${3:-}"
    local args=(--config - -sS -m 120 -X "$method" -o "$WORK/resp.json" -w '%{http_code}')
    [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data-binary "$data")
    HTTP_CODE="$(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl "${args[@]}" "http://127.0.0.1:$PORT$path")" || HTTP_CODE="000"
}

# Wait for a line to hold a value (a port) and print it.
wait_for() {
    local value=""
    for _ in $(seq 1 150); do
        value="$(sed -n "$2" "$1" 2>/dev/null | head -1)"
        if [ -n "$value" ]; then printf '%s' "$value"; return 0; fi
        sleep 0.2
    done
    return 1
}

outbox_count() { find "$SIM_DIR/outbox" -name '*.eml' 2>/dev/null | wc -l | tr -d ' '; }

provider_block
write_agents
# The demo world: the fictional mailbox of the freelancer.
sbx "$AUXFAKEMAIL" demo --dir "$SIM_DIR" --world --force >"$WORK/demo.log" 2>&1 || red "the demo world could not be written: $(tail -n 2 "$WORK/demo.log")"
sbx_bg "$AUXFAKEMAIL" serve --dir "$SIM_DIR" --imap-port 0 --smtp-port 0 >"$WORK/fakemail.log" 2>&1
FAKEMAIL_PID=$!
IMAP_PORT="$(wait_for "$WORK/fakemail.log" 's/^fakemail imap=127\.0\.0\.1:\([0-9][0-9]*\) .*/\1/p')" || red "aux-fakemail never announced its IMAP port: $(tail -n 2 "$WORK/fakemail.log")"
SMTP_PORT="$(wait_for "$WORK/fakemail.log" 's/^fakemail imap=.* smtp=127\.0\.0\.1:\([0-9][0-9]*\) .*/\1/p')" || red "aux-fakemail never announced its SMTP port"
CA_FILE="$SIM_DIR/cert.pem"
[ -s "$CA_FILE" ] || red "aux-fakemail wrote no CA file"
write_config open
# The contacts of the demo world: the gate needs them, the card is built from them.
python3 -I "$TOOLKIT" contacts "$WORK/contacts.vcf"
sbx "$AUX" contacts import "$WORK/contacts.vcf" >"$WORK/import.log" 2>&1 || echo "e2e: the contacts could not be imported: $(tail -n 1 "$WORK/import.log")" >&2
sbx_bg "$AUXD" >"$WORK/auxd.log" 2>&1
AUXD_PID=$!
PORT="$(wait_for "$WORK/auxd.log" 's/.*auxd api on http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p')" || red "auxd never announced its API port: $(tail -n 3 "$WORK/auxd.log")"
TOKEN="$(tr -d '\n' <"$AUX_HOME/api.token")"
# The calendar: two meetings today and one tomorrow (which must not show), and two reminders (one done). The instants are relative to now, like the app's.
python3 -I "$TOOLKIT" calendar "$WORK/calendar.json"
api POST /v1/apple-eventkit/snapshot "$(cat "$WORK/calendar.json")"
[ "$HTTP_CODE" = 204 ] || red "the calendar snapshot was refused: HTTP $HTTP_CODE"
# The client card: the same code path the daemon's 30-minute job uses.
sbx_cli "$AUX" crm timeline refresh >"$WORK/refresh.log" 2>&1 || echo "e2e: the CRM timeline refresh failed: $(tail -n 1 "$WORK/refresh.log")" >&2

PASSED=0
TOTAL=0
for file in "$SCENARIOS"/*.toml; do
    name="$(basename "$file" .toml)"
    [ -n "$ONLY" ] && [ "$ONLY" != "$name" ] && continue
    TOTAL=$((TOTAL + 1))
    # A refused scenario stops the run: a test that cannot fail must not look green.
    plan="$(python3 -I "$TOOLKIT" plan "$file")" || red "scenario $name refused by plan"
    IFS=$'\t' read -r plan_mode plan_agent plan_turns <<<"$plan"
    write_config "$plan_mode"
    # A fresh thread per scenario: the scenarios never see each other.
    api POST "/v1/threads/$plan_agent/new" ""
    [ "$HTTP_CODE" = 200 ] || red "the thread for $name could not be started: HTTP $HTTP_CODE"
    session="$(jq -r .id "$WORK/resp.json")"
    : >"$WORK/turns.jsonl"
    before="$(wc -c <"$BODIES")"
    while IFS= read -r content; do
        # The turn runs in the background: a turn that asks for an approval
        # blocks until the owner answers it.
        printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" |
            curl --config - -sS -m 180 -X POST -o "$WORK/turn.body" -w '%{http_code}' \
                -H 'Content-Type: application/json' \
                --data-binary "$(jq -cn --arg c "$content" '{content: $c}')" \
                "http://127.0.0.1:$PORT/v1/threads/$session/messages" >"$WORK/turn.code" 2>"$WORK/turn.err" &
        TURN_PID=$!
        approvals=0
        for _ in $(seq 1 600); do
            kill -0 "$TURN_PID" 2>/dev/null || break
            api GET "/v1/approvals?state=pending"
            if [ "$HTTP_CODE" = 200 ] && [ "$(jq length "$WORK/resp.json")" -gt 0 ]; then
                approvals=$((approvals + 1))
                # The owner says no: nothing may leave the sandbox.
                api POST "/v1/approvals/$(jq -r '.[0].id' "$WORK/resp.json")" '{"decision":"deny"}'
            fi
            sleep 0.15
        done
        wait "$TURN_PID" 2>/dev/null || true
        TURN_PID=""
        # The replies are the assistant texts after the last tool result: a
        # "let me check" before a tool call is a step the app folds into the
        # same bubble, not a second answer.
        replies="$(jq -c '(.messages // []) as $m | ([$m | to_entries[] | select(.value.role == "tool") | .key] | max // -1) as $t
            | [$m | to_entries[] | select(.key > $t and .value.role == "assistant") | .value.content | select(. != null and . != "")]' \
            "$WORK/turn.body" 2>/dev/null || echo '[]')"
        jq -cn --argjson replies "$replies" --argjson reply_count "$(jq length <<<"$replies")" \
            --argjson http "$(cat "$WORK/turn.code")" --argjson approvals "$approvals" \
            --argjson sent "$(outbox_count)" \
            '{replies: $replies, reply_count: $reply_count, http: $http, approvals: $approvals, sent: $sent}' \
            >>"$WORK/turns.jsonl"
    done < <(jq -r '.[]' <<<"$plan_turns")
    tail -c "+$((before + 1))" "$BODIES" >"$WORK/scenario-bodies.jsonl" 2>/dev/null || true
    jq -n --slurpfile turns "$WORK/turns.jsonl" --argjson sent "$(outbox_count)" \
        '{turns: $turns, sent: $sent}' >"$WORK/record.json"
    if python3 -I "$TOOLKIT" check "$file" "$WORK/record.json" "$PROVIDER" "$WORK/scenario-bodies.jsonl"; then
        PASSED=$((PASSED + 1))
    fi
done

[ "$TOTAL" -gt 0 ] || red "no scenario ran"
echo "E2E $PASSED/$TOTAL PASS"
[ "$PASSED" = "$TOTAL" ] || exit 1
