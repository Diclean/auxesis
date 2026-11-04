#!/usr/bin/env bash
# scripts/test-package-mac.sh — the acceptance gate for scripts/package-mac.sh.
#
# Runs entirely in a mktemp dir that is deleted at the end (disk hygiene):
#   1. --dry-run writes nothing;
#   2. a real package build into the temp dir (cargo target + swift scratch are
#      in the same temp dir, so nothing lands in the checkout);
#   3. asserts the .app structure, the ad-hoc signature, the embedded daemon,
#      and that both shipped binaries are Mach-O (`file(1)`);
#   3b. a version bump removes older Auxesis-*.dmg/.sha256 from --out;
#   3c. the licence notices and the licence texts (licenses/) are in the
#      bundle, every file of the repository's licences/ folder among them;
#   3d. the build number is an integer (--build, else the commit count) and the
#      app reads it out of the packaged Info.plist;
#   4. mounts the DMG read-only in a temp mountpoint and checks Auxesis.app +
#      the Applications symlink;
#   5. verifies the SHA-256 checksum file;
#   6. shellcheck when installed.
#
# Reuse prebuilt binaries to iterate fast (skips the cargo/swift build):
#   AUXESIS_TEST_DAEMON_BIN=target/release/auxd \
#   AUXESIS_TEST_APP_BIN=.build/release/AuxesisMac bash scripts/test-package-mac.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG="$SCRIPT_DIR/package-mac.sh"
# shellcheck source=lib/guard.sh
source "$SCRIPT_DIR/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

VERSION="9.9.9"
BUILD="4242"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-packtest.XXXXXX")"
DIST="$WORK/dist"
DRY="$WORK/dry"
MNT="$WORK/mnt"
MOUNTED=0
# `mount` lives in /sbin, which is not on every restricted PATH.
MOUNT_BIN="$(command -v mount 2>/dev/null || true)"
[ -n "$MOUNT_BIN" ] || MOUNT_BIN=/sbin/mount
PASS=0
FAIL=0

cleanup() {
  if [ "$MOUNTED" = "1" ]; then
    hdiutil detach -quiet "$MNT" >/dev/null 2>&1 || hdiutil detach -force "$MNT" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ok()  { PASS=$((PASS + 1)); echo "ok: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

echo "== 1. dry-run writes nothing"
DRY_OUT="$(nice -n 15 bash "$PKG" --dry-run --out "$DRY" --version "$VERSION")"
printf '%s\n' "$DRY_OUT"
printf '%s\n' "$DRY_OUT" | grep -q "Auxesis-$VERSION.dmg" && ok "dry-run names the DMG" || bad "dry-run names the DMG"
[ ! -e "$DRY" ] && ok "dry-run created nothing" || bad "dry-run created nothing"

echo "== 1b. the build number"
# Without --build the number is the commit count, so it rises with every
# commit; any integer of 1 or more is accepted, and 0, a negative, a dotted
# version or an empty value is refused. 1 is the floor: the app reads a
# missing or unreadable CFBundleVersion as 1 too, and the updater only needs
# a manifest build that is greater.
COMMIT_COUNT="$(git -C "$REPO_ROOT" rev-list --count HEAD)"
DRY_BUILD="$(printf '%s\n' "$DRY_OUT" | awk '$1 == "build" { print $2; exit }')"
[ "$DRY_BUILD" = "$COMMIT_COUNT" ] && ok "the default build number is the commit count ($COMMIT_COUNT)" \
  || bad "the default build number is the commit count (got '$DRY_BUILD')"
for refused in 0.1.0 0 -1 abc ""; do
  bash "$PKG" --dry-run --out "$DRY" --version "$VERSION" --build "$refused" >/dev/null 2>&1 && bad "'$refused' is refused" || ok "'$refused' is refused"
done
# --plist-only writes the real Info.plist into a throwaway bundle, with no
# build and no signing, so the floor of 1 is checked end to end as an integer.
ONE="$WORK/plist-one/Auxesis.app"
bash "$PKG" --plist-only "$ONE" --version "$VERSION" --build 1 >/dev/null \
  && ok "build 1 is accepted" || bad "build 1 is accepted"
[ "$(plutil -extract CFBundleVersion raw -o - "$ONE/Contents/Info.plist" 2>/dev/null)" = "1" ] \
  && ok "build 1 is written as the integer 1" || bad "build 1 is written as the integer 1"

echo "== 1c. a shallow clone is not a build-number source"
# The commit count in a shallow clone is 1, which is a valid build number but
# not the real one. The packager must refuse the fallback there instead of
# silently packaging build 1 (a full checkout is what CI gives it).
SHIM="$WORK/git-shim"
mkdir -p "$SHIM"
ln -s "$(command -v git)" "$SHIM/git.real"
cat > "$SHIM/git" <<'SHIM'
#!/bin/bash
if [ "$1" = "-C" ] && [ "$3" = "rev-parse" ] && [ "$4" = "--is-shallow-repository" ]; then
  echo true
  exit 0
fi
exec git.real "$@"
SHIM
chmod +x "$SHIM/git"
if PATH="$SHIM:$PATH" AUXESIS_BUILD_NUMBER= bash "$PKG" --dry-run --out "$DRY" --version "$VERSION" >/dev/null 2>&1; then
  bad "a shallow clone is refused as the build-number source"
else
  ok "a shallow clone is refused as the build-number source"
fi
# The refusal must be the shallow clone's own: a packager that failed for
# another reason (a bad version, a missing git) is not a pass.
SHALLOW_OUT="$(PATH="$SHIM:$PATH" AUXESIS_BUILD_NUMBER= bash "$PKG" --dry-run --out "$DRY" --version "$VERSION" 2>&1 || true)"
if grep -q "this is a shallow clone, so the commit count is not the build number" <<<"$SHALLOW_OUT"; then
  ok "the refusal names the shallow clone"
else
  bad "the refusal does not name the shallow clone (got: $SHALLOW_OUT)"
fi

echo "== 2. real package build (temp target + temp scratch)"
export CARGO_TARGET_DIR="$WORK/cargo-target"
export CARGO_INCREMENTAL=0
export AUXESIS_MAC_SCRATCH="$WORK/swift-build"
export AUXESIS_MAC_SWIFT_SANDBOX=0   # SwiftPM's sandbox-exec is blocked in this harness
export CLANG_MODULE_CACHE_PATH="$WORK/clang-cache"
BUILD_ARGS=(--out "$DIST" --version "$VERSION" --build "$BUILD")
[ -n "${AUXESIS_TEST_DAEMON_BIN:-}" ] && BUILD_ARGS+=(--daemon-bin "$AUXESIS_TEST_DAEMON_BIN")
[ -n "${AUXESIS_TEST_APP_BIN:-}" ] && BUILD_ARGS+=(--app-bin "$AUXESIS_TEST_APP_BIN")
# Pre-seed --out with an image of an older version: a version bump must remove
# it so the owner can never drag the stale DMG.
STALE_DMG="$DIST/Auxesis-1.2.3.dmg"
STALE_SHA="$DIST/Auxesis-1.2.3.dmg.sha256"
mkdir -p "$DIST"
: > "$STALE_DMG"
: > "$STALE_SHA"
nice -n 15 bash "$PKG" "${BUILD_ARGS[@]}"

APP="$DIST/Auxesis.app"
DMG="$DIST/Auxesis-$VERSION.dmg"
SHA="$DIST/Auxesis-$VERSION.dmg.sha256"

echo "== 3. .app structure + ad-hoc signature"
check "app bundle exists"              "[ -d '$APP' ]"
check "app binary executable"          "[ -x '$APP/Contents/MacOS/AuxesisMac' ]"
check "Info.plist present"             "[ -f '$APP/Contents/Info.plist' ]"
check "Info.plist lints"               "plutil -lint '$APP/Contents/Info.plist'"
check "bundle id is app.auxesis.mac"   "[ \"\$(plutil -extract CFBundleIdentifier raw -o - '$APP/Contents/Info.plist')\" = 'app.auxesis.mac' ]"
check "asks for Messages with a reason"  "plutil -extract NSAppleEventsUsageDescription raw -o - '$APP/Contents/Info.plist' >/dev/null"
check "version is $VERSION"            "[ \"\$(plutil -extract CFBundleShortVersionString raw -o - '$APP/Contents/Info.plist')\" = '$VERSION' ]"
# The build number is an integer: the app compares it with the build of a
# release manifest, and a dotted version reads as nothing (the app then
# reports 1 for ever and no update is ever offered).
check "build number is $BUILD"         "[ \"\$(plutil -extract CFBundleVersion raw -o - '$APP/Contents/Info.plist')\" = '$BUILD' ]"
check "build number is an integer"     "grep -q '<integer>$BUILD</integer>' '$APP/Contents/Info.plist'"
check "daemon embedded + executable"   "[ -x '$APP/Contents/Resources/bin/auxd' ]"
# The shipped files must be real Mach-O executables, not shell stubs or an
# accidental symlink to a build artifact.
check "app binary is Mach-O"           "file -b '$APP/Contents/MacOS/AuxesisMac' | grep -q 'Mach-O'"
check "embedded daemon is Mach-O"      "file -b '$APP/Contents/Resources/bin/auxd' | grep -q 'Mach-O'"
check "LaunchAgent template lints"     "plutil -lint '$APP/Contents/Resources/dev.auxesis.auxd.plist'"
check "codesign -v passes"             "codesign -v '$APP'"
check "codesign strict verify passes"  "codesign --verify --deep --strict '$APP'"

echo "== 3b. version bump removes stale images from --out"
check "stale older-version dmg removed" "[ ! -e '$STALE_DMG' ]"
check "stale older-version sha removed" "[ ! -e '$STALE_SHA' ]"
check "current-version dmg kept"       "[ -f '$DMG' ]"

echo "== 3c. licence notices in the bundle"
# The app ships its own licence (PolyForm Noncommercial 1.0.0), the NOTICE for
# the components that keep their own, the commercial-use terms, and the
# generated list of the third-party crates.
check "LICENSE in Resources"            "[ -f '$APP/Contents/Resources/LICENSE' ]"
check "LICENSE is the PolyForm text"    "grep -q 'PolyForm Noncommercial License' '$APP/Contents/Resources/LICENSE'"
check "NOTICE in Resources"             "[ -f '$APP/Contents/Resources/NOTICE' ]"
check "NOTICE is not empty"             "[ -s '$APP/Contents/Resources/NOTICE' ]"
check "NOTICE carries the required notice" "grep -q '^Required Notice: Copyright 2026 Diclean (https://github.com/Diclean)' '$APP/Contents/Resources/NOTICE'"
check "COMMERCIAL.md in Resources"      "[ -f '$APP/Contents/Resources/COMMERCIAL.md' ]"
check "third-party list in Resources"   "[ -s '$APP/Contents/Resources/THIRD-PARTY-LICENSES.txt' ]"
check "third-party list names crates"   "grep -qE '^serde ' '$APP/Contents/Resources/THIRD-PARTY-LICENSES.txt'"
# The list at the repository root is published and tracked, so a reader sees
# the licences without building anything; the copy in the bundle is written
# at package time from the same locked graph, so the two must be identical.
check "third-party list is tracked"     "git -C '$REPO_ROOT' ls-files --error-unmatch THIRD-PARTY-LICENSES.txt"
check "published list matches the bundle" "cmp -s '$REPO_ROOT/THIRD-PARTY-LICENSES.txt' '$APP/Contents/Resources/THIRD-PARTY-LICENSES.txt'"

# The full text of every third-party licence ships with the app: NOTICE says
# the text of each licence it names is shipped with the release, and MIT, BSD
# and Apache require it. The texts live in licenses/ (one file per SPDX id,
# verbatim from the SPDX licence-list-data repository) and travel with the
# bundle, next to the notices that name them.
check "licences folder in Resources"    "[ -d '$APP/Contents/Resources/licenses' ]"
for text in "$REPO_ROOT"/licenses/*; do
  [ -e "$text" ] || { bad "the repository has a licences folder"; break; }
  name="$(basename "$text")"
  check "licence $name ships in the bundle"  "[ -f '$APP/Contents/Resources/licenses/$name' ]"
  check "licence $name is the shipped text"  "cmp -s '$REPO_ROOT/licenses/$name' '$APP/Contents/Resources/licenses/$name'"
done
# The licences of the components NOTICE names are among them: a licence
# named in NOTICE whose text is not in the bundle is a broken promise.
for id in Apache-2.0 MIT BSD-3-Clause BSD-2-Clause OFL-1.1; do
  check "NOTICE licence $id ships in the bundle" "[ -f '$APP/Contents/Resources/licenses/$id.txt' ]"
done

echo "== 3d. the app reads the packaged build number"
# The app's own reading of the plist it ships with: AppVersion must return
# the integer the packager wrote, not the fallback 1.
SWIFT_LOG="$WORK/swift-test.log"
AUXESIS_PACKAGED_INFO_PLIST="$APP/Contents/Info.plist" nice -n 15 swift test --disable-sandbox -j 3 \
  --scratch-path "$WORK/swift-build" --cache-path "$WORK/swift-build/swiftpm-cache" \
  --config-path "$WORK/swift-build/swiftpm-config" \
  --security-path "$WORK/swift-build/swiftpm-security" \
  --package-path "$REPO_ROOT/apps/auxesis-mac" --filter AppVersionTests > "$SWIFT_LOG" 2>&1 \
  && ok "the swift suite reads the packaged build number" \
  || { bad "the swift suite reads the packaged build number"; tail -20 "$SWIFT_LOG"; }
grep -q "testPackagedInfoPlistCarriesAnIntegerBuild.*pass" "$SWIFT_LOG" \
  && ok "AppVersion reads the packaged CFBundleVersion" \
  || bad "AppVersion reads the packaged CFBundleVersion"

echo "== 4. DMG (read-only mount, drag-to-Applications layout)"
check "dmg exists"                     "[ -f '$DMG' ]"
mkdir -p "$MNT"
hdiutil attach -readonly -nobrowse -mountpoint "$MNT" "$DMG" >/dev/null && MOUNTED=1
# `mount` prints the resolved path (/private/var/... for a /var mktemp), so
# canonicalise the mountpoint before matching it in the mount table.
MNT_REAL="$(cd "$MNT" 2>/dev/null && pwd -P || printf '%s' "$MNT")"
check "dmg attached"                   "[ '$MOUNTED' = 1 ]"
check "dmg read-only"                  "'$MOUNT_BIN' | grep -F ' on $MNT_REAL ' | grep -q 'read-only'"
check "dmg contains Auxesis.app"       "[ -d '$MNT/Auxesis.app' ]"
check "dmg app has Info.plist"         "[ -f '$MNT/Auxesis.app/Contents/Info.plist' ]"
check "dmg has Applications symlink"   "[ -L '$MNT/Applications' ]"
check "Applications -> /Applications"  "[ \"\$(readlink '$MNT/Applications')\" = '/Applications' ]"

echo "== 5. SHA-256 checksum file"
check "checksum file exists"           "[ -f '$SHA' ]"
check "checksum verifies"              "(cd '$DIST' && shasum -a 256 -c 'Auxesis-$VERSION.dmg.sha256')"

echo "== 6. no live-state calls in the packager (static)"
check "no launchctl call"              "! grep -q launchctl '$PKG'"
check "no security call"               "! grep -qE '(^|[^a-z])security ' '$PKG'"
check "no ~/Library/LaunchAgents write" "! grep -q 'LaunchAgents' '$PKG' || grep -q 'refusing' '$PKG'"

echo "== 7. shellcheck (when available)"
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -x "$PKG" "$0"; then ok "shellcheck clean"; else bad "shellcheck clean"; fi
else
  echo "skip: shellcheck not installed"
fi

echo "-------------------------------------------"
echo "test-package-mac: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ] || exit 1
