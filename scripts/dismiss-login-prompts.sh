#!/usr/bin/env bash
# Dismiss macOS authorization dialogs WITHOUT ever clicking Allow.
# Targets only SecurityAgent / coreautha windows and presses Deny/Cancel/Escape.
# Usage: scripts/dismiss-login-prompts.sh [--watch] [--dry-run]
set -euo pipefail

read -r -d '' APPLESCRIPT <<'APPLESCRIPT' || true
on run argv
  set dry to (item 1 of argv) is "dry"
  set found to 0
  tell application "System Events"
    repeat with pname in {"SecurityAgent", "coreautha"}
      if exists process (pname as text) then
        tell process (pname as text)
          repeat with w in windows
            set found to found + 1
            if not dry then
              try
                perform action "AXRaise" of w
              end try
              try
                click button "Deny" of w
              on error
                try
                  click button "Refuser" of w
                on error
                  try
                    click button "Cancel" of w
                  on error
                    try
                      click button "Annuler" of w
                    on error
                      key code 53
                    end try
                  end try
                end try
              end try
            end if
          end repeat
        end tell
      end if
    end repeat
  end tell
  return found
end run
APPLESCRIPT

run_once() {
  local mode="${1:-allow}"
  osascript -e "$APPLESCRIPT" "$mode" 2>/dev/null || echo 0
}

case "${1:-}" in
  --watch)
    echo "watching for auth dialogs (Ctrl-C to stop; never clicks Allow)..."
    while true; do
      count=$(run_once)
      if [[ "${count:-0}" != "0" ]]; then
        echo "$(date '+%H:%M:%S') dismissed: $count dialog(s)"
      fi
      sleep 1
    done
    ;;
  --dry-run)
    echo "dialogs found (dry-run): $(run_once dry)"
    ;;
  *)
    echo "dismissed: $(run_once)"
    ;;
esac
