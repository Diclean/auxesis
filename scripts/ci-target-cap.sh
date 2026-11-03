#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"

target="${CARGO_TARGET_DIR:?CARGO_TARGET_DIR must be set}"
# Never trust an empty or odd HOME: compare it with the account's real home.
user_home="$(eval printf '%s' "~$(id -un)")"
[[ -n "${HOME:-}" && "$HOME" == /* && "$HOME" != / && "$HOME" == "$user_home" ]] || {
  echo "refusing: HOME (${HOME:-unset}) is not the runner account home" >&2
  exit 2
}
[[ "$target" == "$HOME/Library/Caches/auxesis-ci-target" ]] || {
  echo "unexpected Cargo target dir: $target" >&2
  exit 2
}
mkdir -p "$target"
size_kb="$(du -sk "$target" | awk '{print $1}')"
size_gib="$(awk -v kb="$size_kb" 'BEGIN { printf "%.2f", kb / 1024 / 1024 }')"
echo "Cargo target size before build: ${size_gib} GiB (${size_kb} KiB)"
if (( size_kb > 20 * 1024 * 1024 )); then
  echo "Cargo target exceeds 20 GiB; removing stale target directory"
  rm -rf "$target"
  mkdir -p "$target"
fi
