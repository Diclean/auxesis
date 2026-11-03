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
# The imports are read by the Swift compiler itself
# (`swiftc -frontend -emit-imported-modules`), not by a text pattern: comments,
# attributes (`@testable`, `@_spi(...)`, `@_implementationOnly`), `;`, line
# breaks inside a declaration and `import struct M.X` cannot hide a module.
# The compiler sees the macOS build: an import inside an `#if` branch that is
# inactive on macOS is not listed, so `#if` around an import is refused too.
#
# Only `.swift` sources are allowed in the package: SwiftPM would also compile
# C, C++, Objective-C and assembly files, which this check does not read.
#
# This script is the fast local check. The authoritative one is CI building
# the package for the iOS Simulator (.github/workflows/ci.yml, job `swift`):
# a manifest change that adds sources or unsafe flags is caught there.
#
# Fail-closed: a missing scan root, a missing compiler, a file the compiler
# cannot read or an unreadable tree is a failure, never a clean run.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

cd "$(git rev-parse --show-toplevel)"

scan_root="packages/AuxesisShared/Sources"
allowed="Foundation CoreGraphics CryptoKit"

if [ ! -d "$scan_root" ]; then
    echo "check-shared-imports: scan root '$scan_root' is missing — failing closed" >&2
    exit 1
fi
if ! xcrun --find swiftc >/dev/null 2>&1; then
    echo "check-shared-imports: swiftc is unavailable — refusing to report a clean scan" >&2
    exit 1
fi

fail=0

# Anything SwiftPM compiles that is not Swift is refused outright.
others="$(find "$scan_root" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \
    -o -name '*.m' -o -name '*.mm' -o -name '*.s' -o -name '*.S' -o -name '*.h' -o -name '*.hpp' \
    -o -name '*.modulemap' \) -print)" || {
    echo "check-shared-imports: find failed under $scan_root — failing closed" >&2
    exit 1
}
if [ -n "$others" ]; then
    printf 'FAIL [source] %s — the shared package holds Swift sources only\n' $others >&2
    fail=1
fi

# A symlink or a file name with whitespace could hide a source from the scans
# below (SwiftPM follows symlinks): both are refused outright.
odd="$(find "$scan_root" \( -type l -o -name '*[[:space:]]*' \) -print)" || {
    echo "check-shared-imports: find failed under $scan_root — failing closed" >&2
    exit 1
}
if [ -n "$odd" ]; then
    printf 'FAIL [path] %s — no symlink or whitespace in a shared source path\n' "$odd" >&2
    fail=1
fi

# An import guarded by `#if` would be invisible to the macOS compile below.
while IFS= read -r -d '' file; do
    if awk '/^[[:space:]]*#(if|elseif)/{d++} /^[[:space:]]*#endif/{if(d>0)d--} d>0 && /(^|[^A-Za-z0-9_])import[[:space:]]/{found=1} END{exit !found}' "$file"; then
        printf 'FAIL [if-import] %s — no import inside #if in the shared package\n' "$file" >&2
        fail=1
    fi
done < <(find "$scan_root" -type f -name '*.swift' -print0)

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
swift_files=()
while IFS= read -r -d '' file; do
    swift_files+=("$file")
done < <(find "$scan_root" -type f -name '*.swift' -print0)
if [ "${#swift_files[@]}" -eq 0 ]; then
    echo "check-shared-imports: no Swift file under $scan_root — failing closed" >&2
    exit 1
fi

for file in "${swift_files[@]}"; do
    out="$scratch/imports.txt"
    if ! xcrun swiftc -frontend -emit-imported-modules -module-name AuxesisShared \
        "$file" -o "$out" >"$scratch/err.txt" 2>&1; then
        echo "check-shared-imports: the compiler could not read $file — failing closed" >&2
        cat "$scratch/err.txt" >&2
        exit 1
    fi
    while IFS= read -r module; do
        [ -n "$module" ] || continue
        ok=0
        for name in $allowed; do
            [ "$module" = "$name" ] && ok=1
        done
        if [ "$ok" -ne 1 ]; then
            printf 'FAIL [import] %s imports %s — a shared file may import only %s\n' \
                "$file" "$module" "$(printf '%s, ' $allowed | sed 's/, $//')" >&2
            fail=1
        fi
    done <"$out"
done

if [ "$fail" -ne 0 ]; then
    echo "check-shared-imports: FAIL — the shared package must stay portable" >&2
    exit 1
fi
echo "check-shared-imports: OK — $scan_root imports only Foundation, CoreGraphics and CryptoKit"
