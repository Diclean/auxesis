#!/usr/bin/env bash
# Shared sandbox guard for shell scripts.
#
# Every script in `scripts/` and `apps/*/scripts/` that touches `$HOME`,
# `~/Library` or `~/.auxesis` must source this file. It refuses a
# contradictory environment: `AUXESIS_SANDBOX=1` (a sandbox run) with a
# `HOME` that resolves to the REAL user home — the real `~/Library` and
# `~/.auxesis` would then be modified.
#
# `AUXESIS_GUARD_REAL_HOME` is a test-only seam: when set, both it and the
# OS-database home are checked, so it can only make the guard stricter. The
# real home itself comes from `dscl` (macOS) or `getent` (Linux), never from
# `$HOME`.
#
# Sourcing is inert while `AUXESIS_SANDBOX` is unset: normal runs (launchd,
# a developer shell, clean-caches.sh) are unaffected.

# The OS-database home for this user.
guard_real_home() {
  if [ -n "${AUXESIS_GUARD_REAL_HOME:-}" ]; then
    printf '%s' "$AUXESIS_GUARD_REAL_HOME"
    return 0
  fi
  if command -v dscl >/dev/null 2>&1; then
    dscl . -read "/Users/$(id -un)" NFSHomeDirectory 2>/dev/null | awk '{print $2}'
    return 0
  fi
  if command -v getent >/dev/null 2>&1; then
    getent passwd "$(id -u)" | cut -d: -f6
    return 0
  fi
  printf '%s' "${HOME:-}"
}

# Canonical (symlink-resolved) path when it exists; the raw path otherwise.
guard_canon() {
  local path="${1:-}"
  if [ -z "$path" ]; then
    printf ''
    return 0
  fi
  if [ -d "$path" ]; then
    (cd "$path" 2>/dev/null && pwd -P)
  else
    printf '%s' "$path"
  fi
}

guard_lower() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'
}

# True when `path` equals `base` or lives under it (canonical, case-folded).
guard_under() {
  local path base
  path="$(guard_lower "$(guard_canon "${1:-}")")"
  base="$(guard_lower "$(guard_canon "${2:-}")")"
  [ -n "$base" ] || return 1
  [ "$path" = "$base" ] && return 0
  case "$path" in
    "$base"/*) return 0 ;;
  esac
  return 1
}

guard_refuse() {
  echo "guard.sh: refusing: AUXESIS_SANDBOX=1 but ${1:-HOME} resolves to the real home (<home>) — use a literal mktemp path." >&2
  exit 1
}

if [ "${AUXESIS_SANDBOX:-}" = "1" ]; then
  _guard_real="$(guard_real_home)"
  if [ -n "${AUXESIS_GUARD_REAL_HOME:-}" ] && command -v dscl >/dev/null 2>&1; then
    # Stricter test seam: also check against the OS-database home.
    _guard_os="$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    if [ -n "$_guard_os" ] && guard_under "${HOME:-}" "$_guard_os"; then
      guard_refuse "HOME"
    fi
  fi
  if [ -z "${HOME:-}" ]; then
    guard_refuse "HOME (unset)"
  fi
  if [ -n "$_guard_real" ]; then
    if guard_under "$HOME" "$_guard_real" || guard_under "$HOME" "$_guard_real/.auxesis"; then
      guard_refuse "HOME"
    fi
  fi
fi
