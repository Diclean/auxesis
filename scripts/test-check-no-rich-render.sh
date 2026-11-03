#!/usr/bin/env bash
# Self-test for scripts/check-no-rich-render.sh. Each case copies the scanner
# into a throwaway git tree, plants app sources, and checks the verdict: the
# reviewed SystemOpener passes as committed, and any edit to it, a copy of it
# elsewhere, or a new opener in another file fails. A rotted exception check
# cannot pass as clean.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/aux-richrender-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

opener="apps/auxesis-mac/Sources/AuxesisMac/SystemOpener.swift"
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# A fresh tree holding the scanner, its guard and the reviewed opener.
new_tree() {  # <name>; prints the tree path
  local tree="$work/$1"
  mkdir -p "$tree/scripts/lib" "$tree/apps/auxesis-mac/Sources/AuxesisMac"
  cp "$root/scripts/check-no-rich-render.sh" "$tree/scripts/"
  cp "$root/scripts/lib/guard.sh" "$tree/scripts/lib/"
  cp "$root/$opener" "$tree/$opener"
  printf 'struct Plain {}\n' >"$tree/apps/auxesis-mac/Sources/AuxesisMac/Plain.swift"
  git -C "$tree" init -q
  printf '%s\n' "$tree"
}

expect() {  # <pass|fail> <tree> <case>
  local out status
  out="$(cd "$2" && bash scripts/check-no-rich-render.sh 2>&1)" && status=0 || status=$?
  case "$1" in
    pass) [ "$status" -eq 0 ] || fail "$3: expected a clean scan, got status $status: $out" ;;
    fail) [ "$status" -ne 0 ] || fail "$3: expected a failure, the scan passed" ;;
  esac
}

tree="$(new_tree clean)"
expect pass "$tree" "the reviewed SystemOpener as committed"

tree="$(new_tree edited)"
printf '\nfunc extra(_ text: String) { NSWorkspace.shared.open(URL(string: text)!) }\n' >>"$tree/$opener"
expect fail "$tree" "an opener added to SystemOpener"

tree="$(new_tree replaced)"
sed -i.bak 's/permission.settingsURL/URL(string: someText)!/' "$tree/$opener"
rm -f "$tree/$opener.bak"
expect fail "$tree" "the settings URL replaced in SystemOpener"

tree="$(new_tree bundle)"
sed -i.bak 's/com.apple.MobileSMS/com.example.Other/' "$tree/$opener"
rm -f "$tree/$opener.bak"
expect fail "$tree" "the bundle id changed in SystemOpener"

tree="$(new_tree elsewhere)"
printf 'var image = AsyncImage(url: URL(string: "https://evil.invalid/image.png"))\n' \
  >"$tree/apps/auxesis-mac/Sources/AuxesisMac/Plain.swift"
expect fail "$tree" "a remote image loader in another file"

tree="$(new_tree copied)"
mkdir -p "$tree/apps/auxesis-mac/Sources/Other"
cp "$tree/$opener" "$tree/apps/auxesis-mac/Sources/Other/SystemOpener.swift"
expect fail "$tree" "a copy of SystemOpener under another path"

tree="$(new_tree colon)"
printf 'func open(_ text: String) { NSWorkspace.shared.open(URL(string: text)!) }\n' \
  >"$tree/$opener:Payload.swift"
expect fail "$tree" "a sibling whose name starts with the opener path and a colon"

tree="$(new_tree colon-plain)"
printf 'struct Plain {}\n' >"$tree/apps/auxesis-mac/Sources/AuxesisMac/odd:name.swift"
expect fail "$tree" "any source path with a colon"

echo "test-check-no-rich-render: OK"
