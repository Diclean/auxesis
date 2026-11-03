#!/usr/bin/env bash
# Fail if a shared file reaches for a Mac-only framework.
#
# `packages/AuxesisShared` is the one copy of the models, the theme and the
# pure text helpers. The Mac app links it today; the iPhone app will link the
# same package tomorrow. A shared file that imports AppKit, SwiftUI, EventKit,
# Vision, Darwin or anything else Mac-only would compile on the Mac and break
# the phone build — so the rule is pinned here, and the Swift gate runs it.
#
# Allowed imports: Foundation, CoreGraphics, CryptoKit. Nothing else.
#
# Fail-closed: a missing scan root, an unavailable or broken `grep` or `awk`,
# or an unreadable tree is a failure, never a clean run.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

cd "$(git rev-parse --show-toplevel)"

scan_root="packages/AuxesisShared/Sources"
allowed="Foundation CoreGraphics CryptoKit"

if ! command -v grep >/dev/null 2>&1; then
    echo "check-shared-imports: grep is unavailable — refusing to report a clean scan" >&2
    exit 1
fi
if ! command -v awk >/dev/null 2>&1; then
    echo "check-shared-imports: awk is unavailable — refusing to report a clean scan" >&2
    exit 1
fi
if [ ! -d "$scan_root" ]; then
    echo "check-shared-imports: scan root '$scan_root' is missing — failing closed" >&2
    exit 1
fi

# Candidate lines: an import at the start of the line, after optional
# attributes and access keywords. `// import AppKit` in a comment never
# matches: `/` is not a word character.
candidates="$(grep -rnE --include='*.swift' '^[[:space:]]*([@A-Za-z_][A-Za-z0-9_]*[[:space:]]+)*import[[:space:]]' "$scan_root" 2>&1)" && status=0 || status=$?
if [ "$status" -gt 1 ]; then
    echo "check-shared-imports: grep failed (status $status)" >&2
    printf '%s\n' "$candidates" >&2
    exit 1
fi

# The module each candidate imports: strip the attributes, the `import` keyword
# and the optional declaration kind (`import class Foo.Bar`).
modules="$(printf '%s\n' "$candidates" | awk '
    {
        line = $0
        # Drop the "<path>:<line>:" prefix, keep the rest of the line.
        sub(/^[^:]*:[0-9]+:/, "", line)
        gsub(/^[[:space:]]+/, "", line)
        while (line ~ /^@[A-Za-z_][A-Za-z0-9_]*[[:space:]]+/) {
            sub(/^@[A-Za-z_][A-Za-z0-9_]*[[:space:]]+/, "", line)
        }
        if (line ~ /^(public|internal|package|fileprivate|private)[[:space:]]+/) {
            sub(/^(public|internal|package|fileprivate|private)[[:space:]]+/, "", line)
        }
        sub(/^import[[:space:]]+/, "", line)
        if (line ~ /^(typealias|struct|class|enum|protocol|func|var|let)[[:space:]]/) {
            sub(/^(typealias|struct|class|enum|protocol|func|var|let)[[:space:]]+/, "", line)
        }
        if (match(line, /^[A-Za-z_][A-Za-z0-9_]*/)) {
            print substr(line, 1, RLENGTH)
        }
    }
')" || {
    echo "check-shared-imports: awk failed to read the imports — failing closed" >&2
    exit 1
}

fail=0
while IFS= read -r module; do
    [ -n "$module" ] || continue
    ok=0
    for name in $allowed; do
        case "$module" in
            "$name"|"$name".*) ok=1 ;;
        esac
    done
    if [ "$ok" -ne 1 ]; then
        printf 'FAIL [import] %s — a shared file may import only %s\n' \
            "$module" "$(printf '%s, ' $allowed | sed 's/, $//')" >&2
        fail=1
    fi
done <<<"$modules"

if [ "$fail" -ne 0 ]; then
    echo "check-shared-imports: FAIL — a shared file imports a Mac-only framework" >&2
    exit 1
fi
echo "check-shared-imports: OK — $scan_root imports only Foundation, CoreGraphics and CryptoKit"
