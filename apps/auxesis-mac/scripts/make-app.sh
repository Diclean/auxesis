#!/usr/bin/env bash
# Build a double-clickable Auxesis.app (release) for the owner.
#
#   scripts/make-app.sh          # builds build/Auxesis.app
#   scripts/make-app.sh --open   # ... then opens it
#
# The bundle is a thin shell around the SwiftPM binary: Contents/MacOS/AuxesisMac
# plus a minimal Info.plist (CFBundleIdentifier app.auxesis.mac). Double-clicked
# from Finder it inherits no environment, so it uses the app defaults: AUXESIS_HOME
# unset → the real ~/.auxesis (api.token + config.toml api_port, else port 2893).
# The sandbox run script (run-auxesis-mac.sh) stays the safe one for development:
# debug build, throwaway auxd, never the real home.
#
# Signing: ad-hoc (`codesign --force --deep -s -`) needs no keychain, no identity
# and asks no questions; the script signs only when that succeeds, and otherwise
# prints the Gatekeeper "Open Anyway" step. No other signing is attempted.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../scripts" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${AUXESIS_MAC_BUILD_DIR:-$APP_DIR/build}"
BUNDLE="$BUILD_DIR/Auxesis.app"

echo "building release (nice -n 15 swift build -c release -j 2)…"
nice -n 15 swift build -c release -j 2 --package-path "$APP_DIR"
BIN="$APP_DIR/.build/release/AuxesisMac"
[ -x "$BIN" ] || { echo "make-app: $BIN missing after build" >&2; exit 1; }

rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"
cp "$BIN" "$BUNDLE/Contents/MacOS/AuxesisMac"

# The brand of the app travels with it: the icon the Dock and the Finder
# show, and the agent marks the sidebar and the team map draw.
# The icns is built from the approved 1024 px artwork in Resources by
# apps/auxesis-mac/scripts/make-icon.sh; a missing one would ship an app
# with no icon at all, so the build stops here.
ICON="$APP_DIR/Resources/Auxesis.icns"
[ -f "$ICON" ] || {
  echo "make-app: the app icon is missing: $ICON" >&2
  echo "         build it: apps/auxesis-mac/scripts/make-icon.sh" >&2
  exit 1
}
cp "$ICON" "$BUNDLE/Contents/Resources/Auxesis.icns"

cat > "$BUNDLE/Contents/Info.plist" <<'PLIST'
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
	<string>0.1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
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

plutil -lint "$BUNDLE/Contents/Info.plist" >/dev/null || {
  echo "make-app: Info.plist does not lint" >&2
  exit 1
}

if codesign --force --deep --sign - "$BUNDLE" >/dev/null 2>&1; then
  echo "ad-hoc signed (no identity, no keychain, no prompt)"
else
  echo "codesign unavailable — the app is unsigned."
  echo "If macOS refuses the first open: right-click the app → Open → Open Anyway."
fi

echo "built: $BUNDLE"
echo "double-click it in Finder — it connects to your real ~/.auxesis."
echo "start the service first: build it once from the repo, then run it"
echo "  cargo build -p auxd && ./target/debug/auxd"
echo "packaged app / DMG instead: /Applications/Auxesis.app/Contents/Resources/bin/auxd"
echo "safe sandbox instead: scripts/run-auxesis-mac.sh"

if [ "${1:-}" = "--open" ]; then
  open "$BUNDLE"
fi
