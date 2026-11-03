#!/usr/bin/env bash
# apps/auxesis-mac/scripts/make-icon.sh — build the Mac app icon from the
# approved 1024 px artwork.
#
#   apps/auxesis-mac/scripts/make-icon.sh                # into apps/auxesis-mac/Resources
#   apps/auxesis-mac/scripts/make-icon.sh --out DIR      # into DIR (a check, a scratch copy)
#   apps/auxesis-mac/scripts/make-icon.sh --source PNG   # a different 1024 px source
#
# The source is the owner's approved image, committed at
# apps/auxesis-mac/Resources/app-icon-1024.png. This script never redraws,
# recolours or crops it: it only resizes it with sips and packs the sizes into
# an .icns with iconutil, the two tools macOS already has. Nothing is
# installed, nothing is downloaded, nothing is launched.
#
# It writes, in --out (default: the app's own Resources):
#   AppIcon.iconset/  16/32/64/128/256/512/1024 px, 1x and 2x
#   Auxesis.icns      the file the app bundle reads through CFBundleIconFile
#
# scripts/test-app-icon.sh proves that the committed files are exactly what
# this script produces from the committed source.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$APP_DIR/Resources"
SOURCE="$APP_DIR/Resources/app-icon-1024.png"

while [ $# -gt 0 ]; do
    case "$1" in
        --out)    shift; [ $# -gt 0 ] || { echo "make-icon: --out needs a directory" >&2; exit 2; }; OUT="$1"; shift ;;
        --source) shift; [ $# -gt 0 ] || { echo "make-icon: --source needs a file" >&2; exit 2; }; SOURCE="$1"; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "make-icon: unknown argument '$1' (only --out, --source)" >&2; exit 2 ;;
    esac
done

command -v sips >/dev/null 2>&1 || { echo "make-icon: sips not found (macOS only)" >&2; exit 1; }
command -v iconutil >/dev/null 2>&1 || { echo "make-icon: iconutil not found (macOS only)" >&2; exit 1; }
[ -f "$SOURCE" ] || { echo "make-icon: no source at $SOURCE" >&2; exit 1; }

size="$(sips -g pixelWidth -g pixelHeight "$SOURCE" 2>/dev/null \
    | awk '/pixelWidth/ {w = $2} /pixelHeight/ {h = $2} END {print w "x" h}')"
[ "$size" = "1024x1024" ] || { echo "make-icon: the source must be 1024x1024, got $size" >&2; exit 1; }

SET="$OUT/AppIcon.iconset"
rm -rf "$SET"
mkdir -p "$SET"

# Every macOS icon size: the 1x and the 2x of each step, plus the 1024 px
# master. sips resizes the approved image; it does not redraw it.
resize() { sips -z "$2" "$2" "$SOURCE" --out "$SET/$1" >/dev/null; }
resize icon_16x16.png 16
resize icon_16x16@2x.png 32
resize icon_32x32.png 32
resize icon_32x32@2x.png 64
resize icon_64x64.png 64
resize icon_64x64@2x.png 128
resize icon_128x128.png 128
resize icon_128x128@2x.png 256
resize icon_256x256.png 256
resize icon_256x256@2x.png 512
resize icon_512x512.png 512
resize icon_512x512@2x.png 1024
resize icon_1024x1024.png 1024

iconutil -c icns "$SET" -o "$OUT/Auxesis.icns"

echo "make-icon: wrote $SET and $OUT/Auxesis.icns"
