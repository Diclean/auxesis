#!/usr/bin/env bash
# Fail if the delivered macOS app starts rendering untrusted text richly.
#
# Threat (EchoLeak class): the model's text and anything fetched from outside
# (channels, tools, files) is shown next to the user's own data. If that text
# is rendered as rich content — Markdown, HTML, a web view, a remote image, or
# a link that fetches a URL — a hostile string can exfiltrate what it can see
# without any tap. The delivered app (`apps/auxesis-mac`) therefore shows that
# text as plain `Text(verbatim:)` only, and never opens a URL found in text.
#
# Scope: `apps/auxesis-mac/Sources`, the shipped app.
#
# Fail-closed: a missing scan root, an unavailable or broken `grep`, or an
# unreadable tree is a failure, never a clean run.
#
# Patterns (id — fixed string searched anywhere under the scan root):
#   attributed-markdown  `AttributedString(markdown`   Markdown -> attributed text
#   localized-key-var    `LocalizedStringKey(<variable)` localization key built from a variable
#   wkwebview            `WKWebView`                    embedded web view
#   async-image          `AsyncImage`                  remote image loader
#   link                 `Link(`                       clickable link inside text
#   open-url             `openURL`                     SwiftUI URL opener
#   ns-workspace-open    `NSWorkspace.shared.open`     opening a URL or a file
#   nsattributed-html    `NSAttributedString(html`     HTML -> attributed text
#   on-open-url          `.onOpenURL`                  inbound URL handler
#
# Exceptions — only through a reviewed security change. One entry per reviewed
# file, written as
#   <path relative to the repo root>:<pattern-id>:<sha256 of the whole file>
# The hash pins the reviewed content: any edit to the file fails the gate until
# a new review updates the hash. Add a comment above each entry saying why that
# file cannot open or render untrusted content.
EXCEPTIONS=(
    # SystemOpener opens only a fixed System Settings pane (SetupPermission.settingsURL)
    # and Messages by bundle id; it takes no URL or path from text.
    "apps/auxesis-mac/Sources/AuxesisMac/SystemOpener.swift:ns-workspace-open:ef7a2835f3d929e9d7964b36f5f8c6a96da05b2d09cd5c1789a2eee1549d1cf9"
)
# ---------------------------------------------------------------------------
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

cd "$(git rev-parse --show-toplevel)"

# The shipped app: the Mac package and the shared package it links. The
# shared package is scanned too, because the Mac app now renders model text
# through it (PHONE-1a) — the phone app will as well.
scan_roots=("apps/auxesis-mac/Sources" "packages/AuxesisShared/Sources")

if ! command -v grep >/dev/null 2>&1; then
    echo "check-no-rich-render: grep is unavailable — refusing to report a clean scan" >&2
    exit 1
fi
for scan_root in "${scan_roots[@]}"; do
    if [ ! -d "$scan_root" ]; then
        echo "check-no-rich-render: scan root '$scan_root' is missing — failing closed" >&2
        exit 1
    fi
done

fail=0

# Matches are read as `<path>:<line>:<text>`, so a path holding `:` or a newline
# could pose as an excepted file. No app source may carry either: fail closed.
odd="$(find "${scan_roots[@]}" \( -name '*:*' -o -name "*$'\n'*" \) -print 2>&1)" || {
    echo "check-no-rich-render: find failed under ${scan_roots[*]} — failing closed" >&2
    exit 1
}
if [ -n "$odd" ]; then
    printf 'FAIL [odd-path] %s\n' "$odd" >&2
    fail=1
fi

file_sha256() {  # <path>; prints nothing when no hasher works (fail closed)
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$1" 2>/dev/null | cut -d' ' -f1
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1
    fi
}

is_excepted() {  # <path> <pattern-id>
    local entry sum
    for entry in ${EXCEPTIONS[@]+"${EXCEPTIONS[@]}"}; do
        case "$entry" in
            "$1:$2:"*) ;;
            *) continue ;;
        esac
        sum="$(file_sha256 "$1")"
        if [ -n "$sum" ] && [ "$entry" = "$1:$2:$sum" ]; then
            return 0
        fi
    done
    return 1
}

# Report every fixed-string match under the scan roots that is not excepted.
check_fixed() {  # <pattern-id> <fixed-string>
    local id="$1" pattern="$2" hits status hit file
    hits="$(grep -rnF -- "$pattern" "${scan_roots[@]}" 2>&1)" && status=0 || status=$?
    if [ "$status" -gt 1 ]; then
        echo "check-no-rich-render: grep failed for '$id' (status $status)" >&2
        printf '%s\n' "$hits" >&2
        fail=1
        return 0
    fi
    [ "$status" -eq 1 ] && return 0
    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        file="${hit%%:*}"
        is_excepted "$file" "$id" && continue
        printf 'FAIL [%s] %s\n' "$id" "$hit" >&2
        fail=1
    done <<<"$hits"
}

# `LocalizedStringKey(...)` is allowed only when the argument is a plain,
# non-interpolated literal on the same line. Anything built from a variable is
# a rich-render sink: it is a localization key, and keys are rendered richly.
check_localized_key_var() {
    local id="localized-key-var" hits status hit file rest content remainder
    hits="$(grep -rnF -- 'LocalizedStringKey(' "${scan_roots[@]}" 2>&1)" && status=0 || status=$?
    if [ "$status" -gt 1 ]; then
        echo "check-no-rich-render: grep failed for '$id' (status $status)" >&2
        printf '%s\n' "$hits" >&2
        fail=1
        return 0
    fi
    [ "$status" -eq 1 ] && return 0
    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        file="${hit%%:*}"
        rest="${hit#*:}"     # line:content
        content="${rest#*:}" # content
        # Drop every plain literal occurrence; anything left was built from a
        # variable (or from an interpolated literal).
        remainder="$(printf '%s' "$content" | sed -E 's/LocalizedStringKey\("[^"\\]*"\)//g')"
        case "$remainder" in
            *"LocalizedStringKey("*) ;;
            *) continue ;;
        esac
        is_excepted "$file" "$id" && continue
        printf 'FAIL [%s] %s\n' "$id" "$hit" >&2
        fail=1
    done <<<"$hits"
}

check_fixed "attributed-markdown" 'AttributedString(markdown'
check_localized_key_var
check_fixed "wkwebview" 'WKWebView'
check_fixed "async-image" 'AsyncImage'
check_fixed "link" 'Link('
check_fixed "open-url" 'openURL'
check_fixed "ns-workspace-open" 'NSWorkspace.shared.open'
check_fixed "nsattributed-html" 'NSAttributedString(html'
check_fixed "on-open-url" '.onOpenURL'

if [ "$fail" -ne 0 ]; then
    echo "check-no-rich-render: FAIL — untrusted text must stay plain; see docs/rendering.md" >&2
    exit 1
fi
echo "check-no-rich-render: OK — no rich rendering of text in ${scan_roots[*]}"
