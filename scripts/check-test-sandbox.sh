#!/usr/bin/env bash
# Fail if a test spawns an Auxesis binary without a sandbox API port.
#
# Without AUXESIS_API_PORT the spawned `aux`/`auxd` resolves the default 2893,
# which is the live daemon on the dev Mac (`CONTRIBUTING.md`: binary tests use
# the sandbox env, never the real HOME or port). A file that spawns a binary
# must therefore also set "AUXESIS_API_PORT" in code (not a comment), or call
# the shared `sandbox_command(` helper that sets it. This is a per-file grep, not a per-call check: a file with one bare spawn next to a
# sandboxed one still passes, so review new spawns by hand.
#
#   scripts/check-test-sandbox.sh [root]   root defaults to the repo root
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$root"

# Spawners: any Rust file under crates/ or kernel/ that names an Auxesis binary
# (`CARGO_BIN_EXE_aux*`, `Command::new("aux*")`, `cargo_bin("aux*")`). grep exits
# 1 on no match; anything above 1 is a scan error and fails the gate.
spawn='CARGO_BIN_EXE_aux|Command::new\("aux[a-z-]*"\)|cargo_bin\("aux[a-z-]*"\)'
dirs=(crates)
[[ -d kernel ]] && dirs+=(kernel)
status=0
spawners="$(grep -rlE --include='*.rs' "$spawn" "${dirs[@]}")" || status=$?
if (( status > 1 )); then
    echo "check-test-sandbox: RED — scan failed (grep exit $status)" >&2
    exit 1
fi

bad=()
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    # Code only: a `//` comment naming the variable does not count.
    # (No pipe into `grep -q`: its early exit would SIGPIPE sed under pipefail.)
    code="$(sed -E 's#(^|[^:])//.*$#\1#' "$file")"
    if ! grep -qE '"AUXESIS_API_PORT"|sandbox_command\(' <<<"$code"; then
        bad+=("$file")
    fi
done <<<"$spawners"

if (( ${#bad[@]} )); then
    for file in "${bad[@]}"; do
        echo "check-test-sandbox: $file spawns an Auxesis binary without AUXESIS_API_PORT" >&2
    done
    echo "check-test-sandbox: RED — route the spawn through sandbox_command (see the sandbox line in CONTRIBUTING.md)" >&2
    exit 1
fi
echo "check-test-sandbox: OK ($(grep -c . <<<"$spawners") files spawn an Auxesis binary, all sandboxed)"
