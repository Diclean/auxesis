#!/usr/bin/env bash
# CI helper for the self-hosted runner (WO-05).
#
# target-cap: every CI run on the runner shares ONE CARGO_TARGET_DIR (never one
# per run). Artifacts pile up across branches, so when that directory is larger
# than the cap it is removed before the build. Cargo then rebuilds from scratch:
# slower, never wrong.
#
# Usage: scripts/ci-check.sh target-cap <dir> [cap-gib]   (cap defaults to 40)
set -euo pipefail

usage() {
    echo "usage: $0 target-cap <dir> [cap-gib]" >&2
    exit 2
}

cmd_target_cap() {
    local dir="${1:-}" cap_gib="${2:-40}"
    [ -n "$dir" ] || usage
    case "$dir" in
        /*/ci-target/*) ;;
        *)
            # rm -rf below must only ever reach a dedicated CI target directory.
            echo "target-cap: refusing to manage '$dir': not an absolute path under a ci-target/ directory" >&2
            exit 2
            ;;
    esac

    mkdir -p "$dir"
    local used_kib cap_kib
    used_kib="$(du -sk "$dir" | awk '{print $1}')"
    cap_kib=$((cap_gib * 1024 * 1024))
    if [ "$used_kib" -gt "$cap_kib" ]; then
        echo "target-cap: $dir is $((used_kib / 1024 / 1024)) GiB, over the ${cap_gib} GiB cap; removing it"
        rm -rf -- "$dir"
        mkdir -p "$dir"
    else
        echo "target-cap: $dir is $((used_kib / 1024 / 1024)) GiB (cap ${cap_gib} GiB)"
    fi
}

case "${1:-}" in
    target-cap)
        shift
        cmd_target_cap "$@"
        ;;
    *)
        usage
        ;;
esac
