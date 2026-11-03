#!/usr/bin/env bash
# Egress contract check.
#
# Every reqwest client built in production code must be documented in
# docs/egress.md and listed in its machine-readable allowlist. The allowlist is
# per constructor: one entry is `file::function`, the Rust function that holds
# the constructor. A second client added to an allowlisted file is therefore
# flagged too, not waved through by its file name.
#
# The check is static and offline: it greps source only. It fails CLOSED: a scan
# that cannot see the tree (no git, not a work tree, no scan root, an error from
# git grep, or nothing matched at all) is an error, never a pass.
set -euo pipefail

# Paths and docs are relative to the kernel root, the parent of this script's directory.
cd "$(dirname "$0")/.."

docs="docs/egress.md"

if ! command -v git >/dev/null 2>&1; then
    echo "check-egress: FATAL: git is not on PATH, cannot scan for clients" >&2
    exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "check-egress: FATAL: $(pwd) is not a git work tree, cannot scan for clients" >&2
    exit 1
fi

scan_roots=()
[[ -d crates ]] && scan_roots+=("crates")
[[ -d apps ]] && scan_roots+=("apps")
if [[ "${#scan_roots[@]}" -eq 0 ]]; then
    echo "check-egress: FATAL: no scan root (crates/ or apps/) under $(pwd)" >&2
    exit 1
fi

if [[ ! -f "$docs" ]]; then
    echo "check-egress: FATAL: $docs is missing" >&2
    exit 1
fi

allowlist="$(mktemp)"
matches="$(mktemp)"
trap 'rm -f "$allowlist" "$matches"' EXIT

# Extract the allowlist fenced between the HTML markers in docs/egress.md.
awk '
    /<!-- egress-allowlist:start -->/ { inblock = 1; next }
    /<!-- egress-allowlist:end -->/   { inblock = 0; next }
    inblock { print }
' "$docs" | sed -e 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$' >"$allowlist"

if [[ ! -s "$allowlist" ]]; then
    echo "check-egress: FATAL: no allowlist block found in $docs" >&2
    exit 1
fi

# The Rust function that encloses `file:line`: the last `fn NAME` declared at
# or before that line. A constructor outside any function is `<top-level>`.
enclosing_fn() {
    awk -v target="$2" '
        NR > target { exit }
        /^[[:space:]]*\/\// { next }
        match($0, /(^|[^A-Za-z0-9_])fn[[:space:]]+[A-Za-z0-9_]+/) {
            name = substr($0, RSTART, RLENGTH)
            sub(/^.*fn[[:space:]]+/, "", name)
        }
        END { print (name == "" ? "<top-level>" : name) }
    ' "$1"
}

# A reqwest constructor is `Client::builder(` or `Client::new(` when `Client`
# is the imported reqwest type; `build_client(` is the kernel's own
# SSRF-pinned factory. Requiring a non-identifier character before each name
# keeps `RpcClient::new(` / `WeatherClient::new(` / `my_build_client(` out.
pattern='(^|[^A-Za-z0-9_])(Client::(builder|new)|build_client)\('

found=0
failed=0

# `git grep` exits 0 with matches, 1 with none, and >1 on error. Only 0 and 1
# are a completed scan; anything else means the scan did not happen.
grep_status=0
git grep --untracked -nE "$pattern" -- 'crates/**/src/**' 'apps/**/src/**' >"$matches" ||
    grep_status=$?
if [[ "$grep_status" -gt 1 ]]; then
    echo "check-egress: FATAL: git grep failed (exit $grep_status), the tree was not scanned" >&2
    exit 1
fi

while IFS= read -r match; do
    [[ -z "$match" ]] && continue
    file="${match%%:*}"
    rest="${match#*:}"
    line="${rest%%:*}"
    found=$((found + 1))
    function="$(enclosing_fn "$file" "$line")"
    if ! grep -qxF "$file::$function" "$allowlist"; then
        echo "check-egress: unlisted reqwest client at ${match} (function ${function})" >&2
        failed=1
    fi
done <"$matches"

if [[ "$found" -eq 0 ]]; then
    echo "check-egress: FATAL: no client constructor found under ${scan_roots[*]}/**/src/** — fail closed" >&2
    exit 1
fi

if [[ "$failed" -ne 0 ]]; then
    echo "check-egress: FAIL — add its file::function to docs/egress.md (row + allowlist) or remove the client." >&2
    exit 1
fi

constructors=$(grep -c . "$allowlist")
echo "check-egress: OK — ${found} client constructor(s), ${constructors} allowlisted file::function entr(y/ies)."
