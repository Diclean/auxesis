#!/usr/bin/env bash
# install-disk-guard.sh — user LaunchAgent (no sudo) running disk-guard.sh every 20 min.
#   scripts/install-disk-guard.sh            install / reload
#   scripts/install-disk-guard.sh --uninstall
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # Refuse a contradictory sandbox HOME
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LABEL=com.auxesis.disk-guard
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
UID_=$(id -u)
if [ "${1:-}" = "--uninstall" ]; then
  launchctl bootout "gui/$UID_/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"; echo "removed $LABEL"; exit 0
fi
mkdir -p "$HOME/Library/LaunchAgents"
# The agent runs without a shell profile: the machine's tools dir
# (AUX_OPS_DIR) is baked into the plist when it is set, so the cache-cleaning
# step of disk-guard.sh keeps working under launchd.
OPS_ENV=""
if [ -n "${AUX_OPS_DIR:-}" ]; then
  OPS_ENV="<key>AUX_OPS_DIR</key><string>$(printf '%s' "$AUX_OPS_DIR" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')</string>"
fi
cat > "$PLIST" <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$REPO/scripts/disk-guard.sh</string></array>
  <key>StartInterval</key><integer>1200</integer>
  <key>RunAtLoad</key><true/>
  <key>Nice</key><integer>10</integer>
  <key>LowPriorityIO</key><true/>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin</string>${OPS_ENV}</dict>
</dict></plist>
P
launchctl bootout "gui/$UID_/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$UID_" "$PLIST"
echo "installed $LABEL (every 20 min). log: ~/Library/Logs/auxesis-disk-guard.log"
