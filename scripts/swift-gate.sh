#!/usr/bin/env bash
# Swift gate — runs the product's macOS Swift build and tests.
#
#   packages/AuxesisShared : the shared-import rule (Foundation, CoreGraphics,
#                             CryptoKit only)
#   apps/auxesis-mac : swift build, then swift test --disable-sandbox -j 3
#
# macOS only. scripts/precheck.sh calls this script for every code change;
# Rust build gates also run on the Mac with cargo.
#
# Offline and non-invasive: the tests are headless unit tests over models,
# copy, palette, the loopback guard and the token-file reader. They never touch
# the real macOS Keychain, a real provider, or the network. SwiftPM's own
# sandbox-exec is disabled (it is blocked in restricted environments) and every
# SwiftPM cache/config/security path is pinned inside each package's
# gitignored `.build` dir, so nothing lands in the owner's ~/Library.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

repo_root="$(git rev-parse --show-toplevel)"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "swift-gate: requires macOS." >&2
    echo "            Run this gate on the Mac runner." >&2
    exit 2
fi
if ! command -v swift >/dev/null 2>&1; then
    echo "swift-gate: 'swift' not found — install the Xcode Command Line Tools." >&2
    exit 2
fi

# Keep the whole SwiftPM state beside the package (gitignored by each app), so
# `--disable-sandbox` cannot spill caches into ~/Library.
swiftpm_paths=(
    --scratch-path .build
    --cache-path .build/swiftpm-cache
    --config-path .build/swiftpm-config
    --security-path .build/swiftpm-security
)

echo "swift-gate: packages/AuxesisShared — shared imports"
(
    cd "$repo_root"
    nice -n 15 scripts/check-shared-imports.sh
)

echo "swift-gate: apps/auxesis-mac — swift build"
(
    cd "$repo_root/apps/auxesis-mac"
    nice -n 15 swift build --disable-sandbox "${swiftpm_paths[@]}"
)

echo "swift-gate: apps/auxesis-mac — swift test --disable-sandbox -j 3"
(
    cd "$repo_root/apps/auxesis-mac"
    nice -n 15 swift test --disable-sandbox -j 3 "${swiftpm_paths[@]}"
)

echo "swift-gate: OK"
