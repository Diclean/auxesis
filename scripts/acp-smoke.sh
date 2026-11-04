#!/usr/bin/env bash
# Manual smoke: ONE real turn against the owner's OpenCode login.
#
# NOT run in CI. NOT run by automation. Makes exactly one attempt — if it
# fails, capture the output and stop (do not retry).
#
# It never reads credentials: it only checks that `opencode` is installed and
# that its data directory exists, then lets the sandboxed child use its own
# login through a read-only vendor data dir.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # Refuse a contradictory sandbox HOME

prompt="${1:-say ok}"

if ! command -v opencode >/dev/null 2>&1; then
    echo "SKIP: opencode is not installed; nothing to smoke."
    exit 0
fi
opencode_bin="$(command -v opencode)"

vendor="${HOME}/.local/share/opencode"
if [[ ! -d "$vendor" ]]; then
    echo "SKIP: $vendor does not exist; log in with 'opencode auth login' first."
    exit 0
fi

repo_root="$(git rev-parse --show-toplevel)"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/aux-acp-smoke.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

echo "ACP-A0 smoke: ONE live turn (prompt: $prompt); no retry."
echo "scratch workspace: $workdir/ws"

cd "$repo_root"
AUX_ACP_COMMAND="$opencode_bin" \
AUX_ACP_WORKSPACE="$workdir/ws" \
AUX_ACP_VENDOR_DATA="$vendor" \
    cargo run -q -p aux-acp --example acp-smoke -- "$prompt"

echo "ACP-A0 smoke finished."
