#!/usr/bin/env bash
# Self-test for the release half of the CI build lock (CI-LOCK-RMDIR).
#
# scripts/ci-build-lock.sh release must remove the lock this job took, treat an
# absent lock as done (a cancelled run, a re-run), and leave another builder's
# or an unmarked lock alone. Throwaway lock dirs only; no real build lock.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release="$root/scripts/ci-build-lock.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-build-lock-check.XXXXXX")"
trap 'rm -rf "$work"' EXIT

lock="$work/build.lock"
export AUXESIS_BUILD_LOCK_DIR="$lock"
fail=0
fail_case() {
    echo "FAIL: $*" >&2
    fail=1
}

# A lock this job took is released, marker included.
mkdir "$lock"
printf 'job-1\n' >"$lock.owner"
AUXESIS_BUILD_LOCK_OWNER=job-1 "$release" release >/dev/null
[[ ! -e "$lock" ]] || fail_case "the job's own lock was not released"
[[ ! -e "$lock.owner" ]] || fail_case "the job's own marker was not removed"

# Absent: a cancelled run or a re-run is already done, not a red job.
AUXESIS_BUILD_LOCK_OWNER=job-1 "$release" release >/dev/null \
    || fail_case "release failed when the lock was already gone"

# Another job's lock (and its marker) stay.
mkdir "$lock"
printf 'job-2\n' >"$lock.owner"
AUXESIS_BUILD_LOCK_OWNER=job-1 "$release" release >/dev/null 2>&1
[[ -d "$lock" ]] || fail_case "another job's lock was removed"
[[ "$(cat "$lock.owner")" == "job-2" ]] || fail_case "another job's marker was changed"

# A lock with no marker is not ours: never guess and remove it.
rm -f "$lock.owner"
AUXESIS_BUILD_LOCK_OWNER=job-1 "$release" release >/dev/null 2>&1
[[ -d "$lock" ]] || fail_case "an unmarked lock was removed"

# No recorded owner cannot match any marker.
printf 'job-1\n' >"$lock.owner"
AUXESIS_BUILD_LOCK_OWNER= "$release" release >/dev/null 2>&1
[[ -d "$lock" ]] || fail_case "a lock was removed without a recorded owner"

exit "$fail"
