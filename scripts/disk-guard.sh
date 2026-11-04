#!/usr/bin/env bash

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # Refuse a contradictory sandbox HOME
# disk-guard.sh — keeps the Mac's data volume healthy while agent fleets build.
# Run by a user LaunchAgent every 20 min (scripts/install-disk-guard.sh), or by hand.
#   WARN (default 75 %): clean stale temp workspaces (AGE 60), drop cargo incremental dirs,
#                        drop idle worktree targets (>48 h untouched).
#   HARD (default 85 %): aggressive pass (AGE 20, drop every idle worktree target) +
#                        macOS notification + flag file ~/.auxesis/DISK_ALERT (the maintainer stops new work).
# Never touches source, git history, active (recently modified / in-use) dirs, or anything
# outside our own temp/workspace/target dirs.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WARN="${WARN:-75}"; HARD="${HARD:-85}"
VOL=/System/Volumes/Data
LOG="$HOME/Library/Logs/auxesis-disk-guard.log"
FLAG="$HOME/.auxesis/DISK_ALERT"
mkdir -p "$(dirname "$LOG")" "$(dirname "$FLAG")"
log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$LOG"; }
pct() { df -P "$VOL" | awk 'NR==2{gsub("%","",$5);print $5}'; }
free_gb() { df -Pk "$VOL" | awk 'NR==2{printf "%d",$4/1048576}'; }


# Orphaned test spawns (a sandbox/breaker test once left `yes` pegging a core for 26 min):
# kill `yes` processes whose parent is launchd (orphans) and that ran for more than 5 minutes.
reap_strays() {
  ps -axo pid=,ppid=,etime=,comm= 2>/dev/null | while read -r pid ppid et comm; do
    [ "$comm" = "yes" ] || continue
    [ "$ppid" = "1" ] || continue
    case "$et" in *-*|*:*:*) old=1 ;; *) m=${et%%:*}; [ "${m:-0}" -ge 5 ] && old=1 || old=0 ;; esac
    [ "${old:-0}" = "1" ] && { kill "$pid" 2>/dev/null; log "reaped orphan yes pid=$pid"; }
  done
}
reap_strays

before=$(pct)
# 1) always: stale agent temp workspaces. The machine's own cache cleaner does
#    this step when one is configured (AUX_OPS_DIR or CLEAN_CACHES). Without
#    one the step is skipped, but never silently: one line says so, and the
#    cleanup this script does by itself goes on as it always did (the stray
#    reaper above, the idle worktree targets at the thresholds below).
clean_caches="${CLEAN_CACHES:-${AUX_OPS_DIR:+$AUX_OPS_DIR/scripts/clean-caches.sh}}"
if [ -n "$clean_caches" ] && [ -x "$clean_caches" ]; then
  clean_caches_run() { # clean_caches_run <age in minutes>
    AGE_MIN="$1" "$clean_caches" --apply >/dev/null 2>&1 || true
  }
else
  clean_caches_run() { :; }
  echo "disk-guard: no cleaner configured (set AUX_OPS_DIR or CLEAN_CACHES), cleanup skipped" >&2
  log "no cleaner configured (set AUX_OPS_DIR or CLEAN_CACHES), cleanup skipped"
fi
clean_caches_run 120

prune_targets() { # $1 = idle minutes before a worktree target is dropped
  local idle=$1 wt
  git -C "$REPO" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2}' | while read -r wt; do
    t="$wt/target"; [ -d "$t" ] || continue
    # incremental caches are always safe to drop (rebuilt on demand)
    find "$t" -maxdepth 2 -type d -name incremental -mmin +20 -exec rm -rf {} + 2>/dev/null
    # whole target of an idle worktree
    if [ -z "$(find "$t" -mmin -"$idle" -print -quit 2>/dev/null)" ] && ! ps -axo command | grep -F -- "$wt" | grep -v -e grep -e disk-guard | grep -q .; then
      log "drop idle target $t"; rm -rf -- "$t"
    fi
  done
}

now=$(pct)
if [ "$now" -ge "$WARN" ]; then
  clean_caches_run 60
  prune_targets 2880
fi
now=$(pct)
if [ "$now" -ge "$HARD" ]; then
  clean_caches_run 20
  prune_targets 120
fi
now=$(pct)
if [ "$now" -ge "$HARD" ]; then
  printf '%s data volume at %s%% (%s GB free)\n' "$(date '+%F %T')" "$now" "$(free_gb)" > "$FLAG"
  /usr/bin/osascript -e "display notification \"Disk at ${now}% — new agent work paused until it drops\" with title \"Auxesis disk guard\"" >/dev/null 2>&1 || true
  log "ALERT disk ${now}% after cleanup (was ${before}%)"
  exit 2
fi
rm -f "$FLAG"
log "ok disk ${before}% -> ${now}% ($(free_gb) GB free)"
