#!/usr/bin/env bash
# scripts/package-mac.sh — build Auxesis.app + a drag-to-Applications DMG.
#
#   scripts/package-mac.sh                     # build + sign + DMG in dist/
#   scripts/package-mac.sh --dry-run           # print the plan, write nothing
#   scripts/package-mac.sh --out /tmp/x        # different output directory
#   scripts/package-mac.sh --version 0.2.0     # override the Cargo version
#   scripts/package-mac.sh --build 42          # override the build number
#   scripts/package-mac.sh --daemon-bin P      # reuse a prebuilt auxd
#   scripts/package-mac.sh --app-bin P         # reuse a prebuilt AuxesisMac
#
# What it does, in order:
#   1. builds `auxd` (release) with CARGO_BUILD_JOBS=3 and `nice -n 15`;
#   2. builds the SwiftUI app (release, -j 2) with an optional scratch path;
#   3. assembles Auxesis.app: Contents/MacOS/AuxesisMac + the daemon in
#      Contents/Resources/bin/auxd (+ a LaunchAgent template the app can use)
#      and the licence notices (LICENSE, NOTICE, THIRD-PARTY-LICENSES.txt) in
#      Contents/Resources;
#   4. ad-hoc signs the bundle (`codesign --force --deep -s -`) — no identity,
#      no keychain, no prompt;
#   5. leaves the signed dist/Auxesis.app next to the image (inspect it or drag
#      it yourself) and writes dist/Auxesis-<version>.dmg (UDZO, read-only) with
#      an `Applications` symlink for drag-to-Applications;
#   5b. removes older `Auxesis-*.dmg`/`.sha256` images of other versions from
#      --out, so a stale image can never be mistaken for the new one;
#   6. writes dist/Auxesis-<version>.dmg.sha256.
#
# The build number (CFBundleVersion) is an integer of 1 or more: --build, else
# AUXESIS_BUILD_NUMBER, else the commit count (never a shallow clone's count).
#
# Hard rules honoured here: this script NEVER writes to ~/Library/LaunchAgents,
# ~/.auxesis or the Keychain; it never installs anything on the machine, never
# uses `curl | bash`, and never launches the app. Everything outside --out lives
# in a mktemp staging dir that is deleted on exit.
set -euo pipefail

SCRIPT_SOURCE="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIRNAME="$(dirname -- "$SCRIPT_SOURCE")"
SCRIPT_DIR="$(cd -- "$SCRIPT_DIRNAME" 2>/dev/null && pwd || true)"
# An empty dirname/pwd would silently point REPO_ROOT (and every build, staging
# and output path) at the wrong tree; fail loudly instead of packing the wrong
# checkout. (Bash's `cd ""` succeeds and stays put, so it must be checked here.)
if [ -z "$SCRIPT_SOURCE" ] || [ -z "$SCRIPT_DIRNAME" ] || [ -z "$SCRIPT_DIR" ]; then
  echo "package-mac: cannot resolve the script directory (source='${SCRIPT_SOURCE}' dirname='${SCRIPT_DIRNAME}' resolved='${SCRIPT_DIR}')" >&2
  exit 1
fi
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/guard.sh
source "$SCRIPT_DIR/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

die() { echo "package-mac: $*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Usage: scripts/package-mac.sh [options]

  --dry-run            print what would happen; create/modify nothing
  --out DIR            output directory (default: <repo>/dist)
  --version V          bundle + DMG version (default: Cargo [workspace.package])
  --build N            integer build number, 1 or more (default: the commit count)
  --plist-only APP     write only APP/Contents/Info.plist (test seam; nothing
                       is built, signed or imaged)
  --daemon-bin PATH    reuse a prebuilt auxd instead of building it
  --app-bin PATH       reuse a prebuilt AuxesisMac instead of building it
  --no-build           never invoke cargo/swift (requires --app-bin + --daemon-bin)
  --aux-bin PATH       optionally embed the `aux` CLI at Resources/bin/aux
  --keep-staging       keep the mktemp staging dir (debugging)
  -h, --help           this help

Environment: CARGO_TARGET_DIR, CARGO_BUILD_JOBS, AUXESIS_MAC_SCRATCH,
             AUXESIS_BUILD_NUMBER (the build number, when --build is absent),
             AUXESIS_MAC_SWIFT_SANDBOX=0 (restricted builders: no SwiftPM sandbox).
USAGE
}

DRY_RUN=0
NO_BUILD=0
KEEP_STAGING=0
OUT=""
VERSION=""
BUILD=""
PLIST_ONLY=""
APP_BIN=""
DAEMON_BIN=""
AUX_BIN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --out) shift; [ $# -gt 0 ] || die "--out needs a directory"; OUT="$1" ;;
    --version) shift; [ $# -gt 0 ] || die "--version needs a value"; VERSION="$1" ;;
    --build) shift; [ $# -gt 0 ] && [ -n "$1" ] || die "--build needs a number"; BUILD="$1" ;;
    --plist-only) shift; [ $# -gt 0 ] && [ -n "$1" ] || die "--plist-only needs a bundle path"; PLIST_ONLY="$1" ;;
    --daemon-bin) shift; [ $# -gt 0 ] || die "--daemon-bin needs a path"; DAEMON_BIN="$1" ;;
    --app-bin) shift; [ $# -gt 0 ] || die "--app-bin needs a path"; APP_BIN="$1" ;;
    --aux-bin) shift; [ $# -gt 0 ] || die "--aux-bin needs a path"; AUX_BIN="$1" ;;
    --no-build) NO_BUILD=1 ;;
    --keep-staging) KEEP_STAGING=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

# --- version -----------------------------------------------------------------
workspace_version() {
  awk '
    /^\[workspace\.package\]/ { in_block = 1; next }
    /^\[/ { in_block = 0 }
    in_block && /^version[[:space:]]*=/ {
      line = $0
      sub(/^[^=]*=[[:space:]]*/, "", line)
      gsub(/["[:space:]]/, "", line)
      print line
      exit
    }
  ' "$REPO_ROOT/Cargo.toml"
}
[ -n "$VERSION" ] || VERSION="$(workspace_version)"
[ -n "$VERSION" ] || die "could not read the workspace version from Cargo.toml (pass --version)"
case "$VERSION" in
  *[!A-Za-z0-9._-]*) die "refusing a version with unsafe characters: $VERSION" ;;
esac

# --- build number ------------------------------------------------------------
# CFBundleVersion is an integer of 1 or more: the app compares it with the
# build of a release manifest, and a dotted version reads as nothing. It comes
# from --build, else AUXESIS_BUILD_NUMBER, else the commit count, so it rises
# with every commit. A shallow clone's count is 1, which would pass for a real
# build number, so never default to it.
BUILD="${BUILD:-${AUXESIS_BUILD_NUMBER:-}}"
if [ -n "$BUILD" ]; then
  case "$BUILD" in
    ''|*[!0-9]*) die "the build number must be an integer of 1 or more: $BUILD" ;;
  esac
else
  if [ "$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository 2>/dev/null || true)" = "true" ]; then
    die "this is a shallow clone, so the commit count is not the build number: pass --build N, set AUXESIS_BUILD_NUMBER, or fetch the full history (git fetch --unshallow)"
  fi
  BUILD="$(git -C "$REPO_ROOT" rev-list --count HEAD 2>/dev/null || true)"
  [ -n "$BUILD" ] || die "no build number: pass --build N or set AUXESIS_BUILD_NUMBER"
  case "$BUILD" in
    ''|*[!0-9]*) die "the commit count is not an integer: $BUILD" ;;
  esac
fi
[ "$BUILD" -ge 1 ] || die "the build number must be 1 or more: $BUILD"

# The Info.plist every bundle ships. It lives in one place so --plist-only can
# hand the packaged-plist test the exact file package-mac.sh writes, with no
# build and no signing.
write_info_plist() {
  local path="$1"
  cat > "$path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleIdentifier</key>
	<string>app.auxesis.mac</string>
	<key>CFBundleName</key>
	<string>Auxesis</string>
	<key>CFBundleDisplayName</key>
	<string>Auxesis</string>
	<key>CFBundleExecutable</key>
	<string>AuxesisMac</string>
	<key>CFBundleIconFile</key>
	<string>Auxesis.icns</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$VERSION</string>
	<key>CFBundleVersion</key>
	<integer>$BUILD</integer>
	<key>LSMinimumSystemVersion</key>
	<string>14.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSCalendarsFullAccessUsageDescription</key>
	<string>Auxesis reads your upcoming events for the morning brief and to plan meetings.</string>
	<key>NSRemindersFullAccessUsageDescription</key>
	<string>Auxesis reads your upcoming reminders for the morning brief.</string>
	<key>NSAppleEventsUsageDescription</key>
	<string>Auxesis uses Messages to text you, for example to ask for your yes.</string>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.productivity</string>
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
</dict>
</plist>
PLIST
}

# --- output path guard -------------------------------------------------------
OUT="${OUT:-$REPO_ROOT/dist}"
[ -n "$OUT" ] || die "empty --out"
case "$OUT" in
  /) die "refusing to use / as --out" ;;
esac
REAL_HOME="$(guard_real_home)"
refuse_out() {
  local label="$1" path="$2"
  [ -n "$path" ] || return 0
  if [ -n "$REAL_HOME" ] && { guard_under "$OUT" "$path" || guard_under "$(dirname "$OUT")" "$path"; }; then
    die "refusing: --out resolves into $label ($path) — this script never touches the owner's live state"
  fi
}
refuse_out "~/Library/LaunchAgents" "$REAL_HOME/Library/LaunchAgents"
refuse_out "~/.auxesis" "$REAL_HOME/.auxesis"
refuse_out "the Keychain directory" "$REAL_HOME/Library/Keychains"

# --- Info.plist only (test seam) ---------------------------------------------
# The packaged-plist tests need the real generator without building a daemon,
# an app or a signature: write the same Contents/Info.plist and stop. The
# bundle path is a throwaway mktemp dir, never the owner's live state.
if [ -n "$PLIST_ONLY" ]; then
  case "$PLIST_ONLY" in
    /*) ;;
    *) PLIST_ONLY="$PWD/$PLIST_ONLY" ;;
  esac
  if [ -n "$REAL_HOME" ] && guard_under "$PLIST_ONLY" "$REAL_HOME"; then
    die "refusing: --plist-only resolves into the owner's home ($PLIST_ONLY) — use a mktemp dir"
  fi
  if [ "$DRY_RUN" = "1" ]; then
    echo "dry-run: would write $PLIST_ONLY/Contents/Info.plist (build $BUILD)"
    exit 0
  fi
  mkdir -p "$PLIST_ONLY/Contents"
  write_info_plist "$PLIST_ONLY/Contents/Info.plist"
  plutil -lint "$PLIST_ONLY/Contents/Info.plist" >/dev/null || die "Info.plist does not lint"
  echo "wrote: $PLIST_ONLY/Contents/Info.plist (build $BUILD)"
  exit 0
fi

DMG_NAME="Auxesis-$VERSION.dmg"
DMG="$OUT/$DMG_NAME"
SHA="$OUT/$DMG_NAME.sha256"

# --- resolve binaries --------------------------------------------------------
CARGO_TARGET="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
APP_BUILD_DIR="$REPO_ROOT/apps/auxesis-mac"
SWIFT_SCRATCH="${AUXESIS_MAC_SCRATCH:-$APP_BUILD_DIR/.build}"

plan() {
  echo "plan:"
  echo "  version     $VERSION"
  echo "  build       $BUILD"
  echo "  out         $OUT"
  echo "  app bin     ${APP_BIN:-<build> $SWIFT_SCRATCH/release/AuxesisMac}"
  echo "  daemon bin  ${DAEMON_BIN:-<build> $CARGO_TARGET/release/auxd}"
  echo "  bundle      Auxesis.app (Contents/MacOS/AuxesisMac + Contents/Resources/bin/auxd)"
  echo "  icon        Contents/Resources/Auxesis.icns"
  echo "  notices     Contents/Resources/{LICENSE,NOTICE,THIRD-PARTY-LICENSES.txt}"
  echo "  app out     $OUT/Auxesis.app"
  echo "  sign        codesign --force --deep -s -"
  echo "  dmg         $DMG (UDZO, Auxesis.app + Applications -> /Applications)"
  echo "  checksum    $SHA"
}

if [ "$DRY_RUN" = "1" ]; then
  plan
  echo "dry-run: nothing was written."
  exit 0
fi

# --- staging -----------------------------------------------------------------
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-package.XXXXXX")"
cleanup() {
  if [ "$KEEP_STAGING" = "1" ]; then
    echo "package-mac: staging kept at $STAGE"
  else
    rm -rf "$STAGE"
  fi
}
trap cleanup EXIT INT TERM

APP="$STAGE/Auxesis.app"
DMG_STAGE="$STAGE/dmg"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin" "$DMG_STAGE"

# --- build daemon ------------------------------------------------------------
if [ -z "$DAEMON_BIN" ]; then
  [ "$NO_BUILD" = "0" ] || die "--no-build needs --daemon-bin"
  echo "building auxd (release, default features, CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-3}, nice -n 15)…"
  ( cd "$REPO_ROOT" && env CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" \
      nice -n 15 cargo build -p auxd --release )
  DAEMON_BIN="$CARGO_TARGET/release/auxd"
fi
[ -x "$DAEMON_BIN" ] || die "daemon binary is not executable: $DAEMON_BIN"

# --- build app ---------------------------------------------------------------
if [ -z "$APP_BIN" ]; then
  [ "$NO_BUILD" = "0" ] || die "--no-build needs --app-bin"
  echo "building AuxesisMac (release, nice -n 15, scratch $SWIFT_SCRATCH)…"
  SWIFT_ARGS=(-c release -j 2 --scratch-path "$SWIFT_SCRATCH" --package-path "$APP_BUILD_DIR")
  # In a restricted/CI sandbox SwiftPM's own sandbox-exec is blocked; setting
  # AUXESIS_MAC_SWIFT_SANDBOX=0 also keeps every SwiftPM cache inside the
  # scratch dir so nothing lands in the owner's ~/Library.
  if [ "${AUXESIS_MAC_SWIFT_SANDBOX:-1}" = "0" ]; then
    SWIFT_ARGS+=(--disable-sandbox
      --cache-path "$SWIFT_SCRATCH/swiftpm-cache"
      --config-path "$SWIFT_SCRATCH/swiftpm-config"
      --security-path "$SWIFT_SCRATCH/swiftpm-security")
  fi
  nice -n 15 swift build "${SWIFT_ARGS[@]}"
  APP_BIN="$SWIFT_SCRATCH/release/AuxesisMac"
fi
[ -x "$APP_BIN" ] || die "app binary is not executable: $APP_BIN"

# --- assemble the bundle -----------------------------------------------------
echo "assembling Auxesis.app…"
cp "$APP_BIN" "$APP/Contents/MacOS/AuxesisMac"
chmod 755 "$APP/Contents/MacOS/AuxesisMac"
cp "$DAEMON_BIN" "$APP/Contents/Resources/bin/auxd"
chmod 755 "$APP/Contents/Resources/bin/auxd"

if [ -z "$AUX_BIN" ] && [ -x "$CARGO_TARGET/release/aux" ]; then
  AUX_BIN="$CARGO_TARGET/release/aux"
fi
if [ -n "$AUX_BIN" ]; then
  [ -x "$AUX_BIN" ] || die "aux CLI is not executable: $AUX_BIN"
  cp "$AUX_BIN" "$APP/Contents/Resources/bin/aux"
  chmod 755 "$APP/Contents/Resources/bin/aux"
fi

# The licence notices travel with the app: the project's own Apache-2.0 text,
# the NOTICE for the components that keep their own licence, and the list of
# the third-party crates the build links. The list is generated from the
# locked graph at package time, so it always matches what is shipped.
# The brand of the app travels with it: the icon the Dock and the Finder
# show, and the agent marks the sidebar and the team map draw.
# The icns is built from the approved 1024 px artwork in Resources by
# apps/auxesis-mac/scripts/make-icon.sh; a missing one would ship an app with
# no icon at all, so the packaging stops here.
[ -f "$APP_BUILD_DIR/Resources/Auxesis.icns" ] \
  || die "the app icon is missing: $APP_BUILD_DIR/Resources/Auxesis.icns (run apps/auxesis-mac/scripts/make-icon.sh)"
cp "$APP_BUILD_DIR/Resources/Auxesis.icns" "$APP/Contents/Resources/Auxesis.icns"

cp "$REPO_ROOT/LICENSE" "$APP/Contents/Resources/LICENSE"
cp "$REPO_ROOT/NOTICE" "$APP/Contents/Resources/NOTICE"
python3 -I "$SCRIPT_DIR/third-party-licenses.py" "$APP/Contents/Resources" \
  || die "could not write the third-party licence list"

# The daemon the app supervises is the one embedded here; the plist is a
# template the app fills in on first run (see docs/INSTALL.fr.md, open item).
cat > "$APP/Contents/Resources/dev.auxesis.auxd.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Template installed by the app on first run; @AUXD@ is the embedded
     Contents/Resources/bin/auxd path and @HOME@ is the owner's ~/.auxesis. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.auxesis.auxd</string>
	<key>ProgramArguments</key>
	<array>
		<string>@AUXD@</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>EnvironmentVariables</key>
	<dict>
		<key>AUXESIS_HOME</key>
		<string>@HOME@</string>
	</dict>
</dict>
</plist>
PLIST

write_info_plist "$APP/Contents/Info.plist"

plutil -lint "$APP/Contents/Info.plist" >/dev/null || die "Info.plist does not lint"
plutil -lint "$APP/Contents/Resources/dev.auxesis.auxd.plist" >/dev/null || die "LaunchAgent template does not lint"

# --- ad-hoc sign -------------------------------------------------------------
echo "ad-hoc signing (no identity, no keychain, no prompt)…"
codesign --force --deep -s - "$APP" >/dev/null 2>&1 || die "codesign failed"
codesign --verify --deep --strict "$APP" 2>/dev/null || die "signature does not verify"

# --- publish the app + build the DMG ----------------------------------------
mkdir -p "$OUT"
if [ "$OUT" = "$REPO_ROOT/dist" ] && [ ! -e "$OUT/.gitignore" ]; then
  printf '*\n' > "$OUT/.gitignore"   # never commit build artifacts
fi

# After a version bump an older image would sit next to the new one and the
# owner could drag the wrong (stale) DMG. Only touch `<out>/Auxesis-*.dmg` and
# their `.sha256`; never any other file in --out.
for stale in "$OUT"/Auxesis-*.dmg "$OUT"/Auxesis-*.dmg.sha256; do
  [ -e "$stale" ] || continue
  case "${stale##*/}" in
    "$DMG_NAME"|"$DMG_NAME.sha256") continue ;;
  esac
  echo "removing stale image from an older version: ${stale##*/}"
  rm -f -- "$stale"
done

# Keep the assembled bundle next to the image: it is the exact thing signed
# above, and the quickest way to inspect a build without mounting the DMG.
echo "publishing Auxesis.app to ${OUT}…"
rm -rf "$OUT/Auxesis.app"
ditto "$APP" "$OUT/Auxesis.app"

echo "building DMG…"
ditto "$APP" "$DMG_STAGE/Auxesis.app"
ln -s /Applications "$DMG_STAGE/Applications"
rm -f "$DMG" "$SHA"
hdiutil create -volname "Auxesis" -srcfolder "$DMG_STAGE" -ov -format UDZO "$DMG" >/dev/null

# --- checksum ----------------------------------------------------------------
( cd "$OUT" && shasum -a 256 "$DMG_NAME" > "$DMG_NAME.sha256" )
( cd "$OUT" && shasum -a 256 -c "$DMG_NAME.sha256" >/dev/null ) || die "checksum does not verify"

echo "built: $OUT/Auxesis.app"
echo "built: $DMG"
echo "checksum: $SHA"
echo "build: $BUILD (put this number in the release manifest as \"build\")"
echo "next: double-click the DMG, drag Auxesis to Applications, then see docs/INSTALL.md (French version: docs/INSTALL.fr.md)"
