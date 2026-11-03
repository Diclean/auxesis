#!/usr/bin/env bash
# scripts/test-app-icon.sh — the acceptance gate for the Mac app icon.
#
# What it proves:
#   1. the approved 1024 px artwork is committed with the app;
#   2. every macOS icon size (16/32/64/128/256/512/1024, 1x and 2x) is in the set;
#   3. Auxesis.icns carries every one of those sizes;
#   4. the artwork is the approved one, unaltered: every set entry is the
#      source resized by sips, and the icns holds exactly that set;
#   5. make-app.sh and package-mac.sh put the icns in the bundle and the
#      Info.plist names it (CFBundleIconFile);
#   6. the icon can be rebuilt from the source: make-icon.sh reproduces the
#      committed files byte for byte.
#
# macOS only (sips, iconutil). It writes nothing outside a temp dir it deletes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$REPO_ROOT/apps/auxesis-mac"
RES="$APP_DIR/Resources"
SOURCE="$RES/app-icon-1024.png"
SET="$RES/AppIcon.iconset"
ICNS="$RES/Auxesis.icns"

if [[ "$(uname -s)" != "Darwin" ]] || ! command -v sips >/dev/null 2>&1 || ! command -v iconutil >/dev/null 2>&1; then
    echo "skip: the app icon gate needs macOS (sips, iconutil)"
    exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-icon-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); echo "ok: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }
# Pixel width of an image, or nothing when sips cannot read it.
px() { sips -g pixelWidth "$1" 2>/dev/null | awk '/pixelWidth/ {print $2}' || true; }
# A file, a string it must contain.
has() { if grep -q -- "$2" "$3" 2>/dev/null; then ok "$1"; else bad "$1"; fi; }

# The icon set: every file name macOS expects, and the pixel size it carries.
SET_FILES=(
  "icon_16x16.png 16"
  "icon_16x16@2x.png 32"
  "icon_32x32.png 32"
  "icon_32x32@2x.png 64"
  "icon_64x64.png 64"
  "icon_64x64@2x.png 128"
  "icon_128x128.png 128"
  "icon_128x128@2x.png 256"
  "icon_256x256.png 256"
  "icon_256x256@2x.png 512"
  "icon_512x512.png 512"
  "icon_512x512@2x.png 1024"
  "icon_1024x1024.png 1024"
)

echo "== 1. the approved source is committed with the app"
if [ -f "$SOURCE" ]; then ok "the 1024 px source is in the repo"; else bad "the 1024 px source is in the repo"; fi
if git -C "$REPO_ROOT" ls-files --error-unmatch "apps/auxesis-mac/Resources/app-icon-1024.png" >/dev/null 2>&1; then
  ok "the source is tracked by git"
else
  bad "the source is tracked by git"
fi
if [ "$(px "$SOURCE")" = "1024" ]; then ok "the source is 1024 px wide"; else bad "the source is 1024 px wide"; fi

echo "== 2. every macOS icon size is in the set"
for entry in "${SET_FILES[@]}"; do
  name="${entry%% *}"
  want="${entry##* }"
  if [ -f "$SET/$name" ] && [ "$(px "$SET/$name")" = "$want" ]; then
    ok "$name is ${want}px"
  else
    bad "$name is ${want}px"
  fi
done

echo "== 3. the icns carries every size"
rm -rf "$WORK/extracted.iconset"
if iconutil -c iconset "$ICNS" -o "$WORK/extracted.iconset" >/dev/null 2>&1; then
  ok "the icns unpacks"
else
  bad "the icns unpacks"
fi
have=""
for f in "$WORK"/extracted.iconset/*.png; do
  [ -f "$f" ] || continue
  w="$(px "$f")"
  [ -n "$w" ] && have="$have $w"
done
for want in 16 32 64 128 256 512 1024; do
  case " $have " in
    *" $want "*) ok "the icns carries ${want}px" ;;
    *) bad "the icns carries ${want}px" ;;
  esac
done

echo "== 4. the artwork is the approved one, unaltered"
# Every set entry must be the source resized by sips: nothing recoloured,
# nothing cropped, nothing redrawn.
for entry in "${SET_FILES[@]}"; do
  name="${entry%% *}"
  want="${entry##* }"
  sips -z "$want" "$want" "$SOURCE" --out "$WORK/resized.png" >/dev/null 2>&1 || true
  if cmp -s "$WORK/resized.png" "$SET/$name"; then
    ok "$name is the source at ${want}px"
  else
    bad "$name is the source at ${want}px"
  fi
done
# The icns must hold exactly the committed set, and its 1024 px entry must be
# the approved pixels, not a look-alike. (BMP, not PNG: iconutil re-encodes the
# entry and drops the colour profile, so the two files differ in metadata while
# carrying the same pixels. The byte-exact chain above is what proves the
# artwork; this one proves the pixels of the packed file.)
if iconutil -c icns "$SET" -o "$WORK/repacked.icns" >/dev/null 2>&1 && cmp -s "$WORK/repacked.icns" "$ICNS"; then
  ok "the icns holds exactly the committed set"
else
  bad "the icns holds exactly the committed set"
fi
sips -s format bmp "$SOURCE" --out "$WORK/source.bmp" >/dev/null 2>&1 || true
sips -s format bmp "$WORK/extracted.iconset/icon_512x512@2x.png" --out "$WORK/icns.bmp" >/dev/null 2>&1 || true
if cmp -s "$WORK/source.bmp" "$WORK/icns.bmp"; then
  ok "the 1024 px entry of the icns is the approved pixels"
else
  bad "the 1024 px entry of the icns is the approved pixels"
fi

echo "== 5. the bundle carries the icon"
has "make-app.sh copies the icns into the bundle"  'Resources/Auxesis.icns' "$APP_DIR/scripts/make-app.sh"
has "make-app.sh names the icon in Info.plist"    'CFBundleIconFile'    "$APP_DIR/scripts/make-app.sh"
has "make-app.sh names Auxesis.icns"              '<string>Auxesis.icns</string>' "$APP_DIR/scripts/make-app.sh"
has "package-mac.sh copies the icns into the bundle" 'Resources/Auxesis.icns' "$SCRIPT_DIR/package-mac.sh"
has "package-mac.sh names the icon in Info.plist"    'CFBundleIconFile'    "$SCRIPT_DIR/package-mac.sh"
has "package-mac.sh names Auxesis.icns"              '<string>Auxesis.icns</string>' "$SCRIPT_DIR/package-mac.sh"

echo "== 6. the icon can be rebuilt from the source"
if bash "$APP_DIR/scripts/make-icon.sh" --out "$WORK/out" >/dev/null 2>&1; then
  ok "make-icon.sh rebuilds the icon"
else
  bad "make-icon.sh rebuilds the icon"
fi
for entry in "${SET_FILES[@]}"; do
  name="${entry%% *}"
  if cmp -s "$WORK/out/AppIcon.iconset/$name" "$SET/$name"; then
    ok "the rebuilt $name is identical"
  else
    bad "the rebuilt $name is identical"
  fi
done
if cmp -s "$WORK/out/Auxesis.icns" "$ICNS"; then
  ok "the rebuilt icns is identical"
else
  bad "the rebuilt icns is identical"
fi

echo "== 7. shellcheck (when available)"
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -x "$SCRIPT_DIR/test-app-icon.sh" "$APP_DIR/scripts/make-icon.sh"; then
    ok "shellcheck clean"
  else
    bad "shellcheck clean"
  fi
else
  echo "skip: shellcheck not installed"
fi

echo "-------------------------------------------"
echo "test-app-icon: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ] || exit 1
