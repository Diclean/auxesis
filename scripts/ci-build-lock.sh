#!/usr/bin/env bash
# The release half of the CI build lock.
#
# The acquire side stays in the workflows: `mkdir /tmp/auxesis-build.lock`,
# then the job writes its `$GITHUB_JOB-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT`
# owner to /tmp/auxesis-build.lock.owner beside the (empty) lock directory.
# This script removes that lock only when the marker still names this job, and
# treats an already released lock as done: a cancelled run or a re-run must not
# turn a green job red, and another builder's lock is never removed.
#
#   scripts/ci-build-lock.sh release
#
# Environment:
#   AUXESIS_BUILD_LOCK_OWNER  the owner acquire recorded; empty means "not ours"
#   AUXESIS_BUILD_LOCK_DIR    the lock path (default /tmp/auxesis-build.lock;
#                             scripts/test-ci-build-lock.sh uses a temp dir)
set -euo pipefail

lock="${AUXESIS_BUILD_LOCK_DIR:-/tmp/auxesis-build.lock}"

if [[ "${1:-}" != release ]]; then
    echo "usage: $0 release" >&2
    exit 2
fi

if [[ ! -d "$lock" ]]; then
    echo "build lock: $lock is already released"
    exit 0
fi

ours="${AUXESIS_BUILD_LOCK_OWNER:-}"
owner="$(cat "$lock.owner" 2>/dev/null || true)"
if [[ -z "$ours" || "$owner" != "$ours" ]]; then
    echo "build lock: $lock was not taken by this job (owner: ${owner:-none}); leaving it" >&2
    exit 0
fi

if ! rm -f "$lock.owner" 2>/dev/null; then
    echo "build lock: cannot remove $lock.owner; leaving $lock" >&2
    exit 0
fi
if rmdir "$lock" 2>/dev/null; then
    echo "build lock: $lock released"
else
    echo "build lock: $lock was claimed by another builder; leaving it" >&2
fi
