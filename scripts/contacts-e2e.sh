#!/usr/bin/env bash
# Contacts end to end, through the real binaries, in a sandbox home.
#
#   scripts/contacts-e2e.sh [BIN_DIR]     (BIN_DIR defaults to target/debug)
#
# 1. One daemon is started on a fresh install (no contacts): a Private turn is
#    refused, and the refusal carries the next step.
# 2. `aux contacts import` stores two fictional files: a vCard, and a vCard 2.1
#    file whose name is quoted-printable (Slovenian).
# 3. The same daemon, with no restart, completes a Private turn that names
#    Camille Exemple and Božidar Hožič, with their addresses.
# 4. The provider body and every file on disk carry no clear name or address.
#
# Everything runs under a mktemp home; the trap removes it on every exit.
# The fake provider is a local Python process run with `python3 -I`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The shared sandbox guard: inert here, but it refuses a sandbox run
# whose HOME resolves to the real home.
# shellcheck source=lib/guard.sh
. "$ROOT/scripts/lib/guard.sh"
BIN="$(cd "${1:-$ROOT/target/debug}" && pwd)"
FIXTURE="$ROOT/crates/aux-cli/tests/fixtures/contacts.vcf"
FIXTURE_QP="$ROOT/crates/aux-cli/tests/fixtures/contacts-qp.vcf"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-contacts-e2e.XXXXXX")"
DAEMON_PID=""
PROVIDER_PID=""

cleanup() {
    [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null || true
    [[ -n "$PROVIDER_PID" ]] && kill "$PROVIDER_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM HUP

umask 077
HOME_DIR="$TMP/home"
AUX_HOME="$HOME_DIR/.auxesis"
LOGS="$TMP/logs"
INPUT="$TMP/input"
mkdir -p "$AUX_HOME" "$LOGS" "$INPUT"
cp "$FIXTURE" "$INPUT/contacts.vcf"
cp "$FIXTURE_QP" "$INPUT/contacts-qp.vcf"

# The sandbox every binary runs under (the literal form the project mandates).
sandbox() {
    env -i HOME="$HOME_DIR" AUXESIS_HOME="$AUX_HOME" AUXESIS_SANDBOX=1 \
        AUXESIS_API_PORT=0 PATH=/usr/bin:/bin:/usr/sbin:/sbin "$@"
}

fail() {
    echo "contacts-e2e: FAIL: $*" >&2
    exit 1
}

cat >"$TMP/fake_provider.py" <<'PY'
import http.server, json, sys

LOG, PORT_FILE = sys.argv[1], sys.argv[2]
REPLY = "E2E-REPLY-OK"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with open(LOG, "ab") as log:
            log.write(body + b"\n")
        request = json.loads(body or b"{}")
        if request.get("stream"):
            chunk = {"id": "e2e", "object": "chat.completion.chunk", "created": 0,
                     "model": "fake-model",
                     "choices": [{"index": 0, "delta": {"role": "assistant", "content": REPLY},
                                  "finish_reason": None}]}
            payload = ("data: " + json.dumps(chunk) + "\n\ndata: [DONE]\n\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
        else:
            payload = json.dumps({"id": "e2e", "object": "chat.completion", "created": 0,
                                  "model": "fake-model",
                                  "choices": [{"index": 0,
                                               "message": {"role": "assistant", "content": REPLY},
                                               "finish_reason": "stop"}],
                                  "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                                            "total_tokens": 2}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(PORT_FILE, "w") as port:
    port.write(str(server.server_address[1]))
server.serve_forever()
PY

python3 -I "$TMP/fake_provider.py" "$LOGS/provider-bodies.jsonl" "$TMP/provider.port" \
    >"$LOGS/provider.out" 2>&1 &
PROVIDER_PID=$!
for _ in $(seq 1 50); do
    [[ -s "$TMP/provider.port" ]] && break
    sleep 0.1
done
[[ -s "$TMP/provider.port" ]] || fail "the fake provider did not start"
PROVIDER_PORT="$(cat "$TMP/provider.port")"

cat >"$AUX_HOME/config.toml" <<TOML
version = 1
default_agent = "main"

[[providers]]
id = "fake"
kind = "openai-compat"
base_url = "http://127.0.0.1:$PROVIDER_PORT/v1"
model = "fake-model"
TOML
printf 'AUX_KEY_FAKE=e2e-fake-key\n' >"$AUX_HOME/.env"
chmod 600 "$AUX_HOME/.env"

MESSAGE="Écris à Camille Exemple (camille.exemple@example.invalid) et à Božidar Hožič (bozidar.hozic@example.invalid) pour confirmer la réunion."
BODY="$(python3 -I -c 'import json, sys; print(json.dumps({"content": sys.argv[1]}))' "$MESSAGE")"

start_daemon() {
    local tag="$1"
    # `env` execs auxd, so $! is the daemon's own pid (a backgrounded function would not be).
    env -i HOME="$HOME_DIR" AUXESIS_HOME="$AUX_HOME" AUXESIS_SANDBOX=1 \
        AUXESIS_API_PORT=0 PATH=/usr/bin:/bin:/usr/sbin:/sbin "$BIN/auxd" \
        >"$LOGS/auxd-$tag.out" 2>"$LOGS/auxd-$tag.err" &
    DAEMON_PID=$!
    local port=""
    for _ in $(seq 1 100); do
        port="$(sed -n 's#^auxd api on http://127.0.0.1:\([0-9]*\)$#\1#p' "$LOGS/auxd-$tag.out" | head -n 1)"
        [[ -n "$port" ]] && break
        sleep 0.1
    done
    if [[ -z "$port" ]]; then
        tail -n 5 "$LOGS/auxd-$tag.err" >&2 || true
        fail "auxd did not announce its API port"
    fi
    API="http://127.0.0.1:$port"
}

stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=""
}

send_private_turn() {
    local out="$1"
    # The bearer header goes to curl on stdin (`--config -`), never on its argv.
    printf 'header = "Authorization: Bearer %s"\n' "$(cat "$AUX_HOME/api.token")" \
        | curl --config - -sS -o "$out" -w '%{http_code}' -X POST "$API/v1/threads/main/messages" \
            -H 'Content-Type: application/json' --data-binary "$BODY"
}

# One daemon for the whole run: it is never restarted, so the import must reach
# it through the reload at the next Private turn.
start_daemon live

# 1. A fresh install has no contacts: the Private turn is refused, with the next step.
status="$(send_private_turn "$TMP/reply-fresh.json")"
[[ "$status" != "200" ]] || fail "a Private turn with no contacts completed (it must be refused)"
grep -q 'aux contacts import <file>' "$TMP/reply-fresh.json" \
    || fail "the refusal does not give the next step"
echo "phase 1: no contacts -> HTTP $status, with the next step: $(head -c 200 "$TMP/reply-fresh.json")"

# 2. Import the two files with the real `aux` binary.
(cd "$INPUT" && sandbox "$BIN/aux" contacts import contacts.vcf --country FR) \
    >"$LOGS/import.out" 2>"$LOGS/import.err" || fail "aux contacts import (vCard) failed"
grep -q 'Stored 4 contacts from this file (4 e-mail addresses, 6 phone numbers)' "$LOGS/import.out" \
    || fail "unexpected import summary for the vCard"
(cd "$INPUT" && sandbox "$BIN/aux" contacts import contacts-qp.vcf --country SI) \
    >"$LOGS/import-qp.out" 2>"$LOGS/import-qp.err" || fail "aux contacts import (quoted-printable) failed"
grep -q 'Stored 1 contacts from this file (1 e-mail addresses, 1 phone numbers)' "$LOGS/import-qp.out" \
    || fail "unexpected import summary for the quoted-printable file"
echo "phase 2: $(head -n 1 "$LOGS/import.out"); $(head -n 1 "$LOGS/import-qp.out")"

# 3. The same daemon, not restarted, mounts the contacts and completes the turn.
status="$(send_private_turn "$TMP/reply.json")"
[[ "$status" == "200" ]] || fail "the Private turn returned HTTP $status: $(cat "$TMP/reply.json")"
grep -q 'E2E-REPLY-OK' "$TMP/reply.json" || fail "the turn did not complete with the provider's reply"
echo "phase 3: the same daemon, after the import -> HTTP 200, the provider reply came back"
stop_daemon

# 4. The provider body is masked, and nothing clear is on disk.
[[ -s "$LOGS/provider-bodies.jsonl" ]] || fail "the provider received no body"
CLEAR='camille|exemple|Camille|Exemple|bozidar|hozic|Božidar|Hožič|Bo=C5|Ho=C5'
if grep -a -E -q "$CLEAR" "$LOGS/provider-bodies.jsonl"; then
    fail "a clear name or address reached the provider"
fi
grep -q '⟦' "$LOGS/provider-bodies.jsonl" || fail "the provider body carries no placeholder"
if grep -a -r -E -l "$CLEAR" "$HOME_DIR" "$LOGS" >"$TMP/hits.txt" 2>/dev/null; then
    cat "$TMP/hits.txt" >&2
    fail "a clear name or address is on disk"
fi
[[ -s "$AUX_HOME/store.db" ]] || fail "the store was not created"
echo "phase 4: the provider body is masked; no clear name or address on disk"
echo "contacts-e2e: OK"
