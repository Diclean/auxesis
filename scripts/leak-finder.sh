#!/usr/bin/env bash
# Run the leak-finder probe (qa/privacy-eval/tests/leak_finder.rs in the
# privacy kernel repository) on the configured build host, and copy its report
# to the report directory.
#
#   scripts/leak-finder.sh [--ref <git ref>] [--cases <n>] [--slot <name>]
#   scripts/leak-finder.sh [--local]
#   scripts/leak-finder.sh --help
#
# Runs the ignored `nightly` test of a clean checkout of <ref> (default: the
# kernel commit the app pins, read from Cargo.lock) in release via
# remote-build.sh, and writes <date>.json/.md.
# The build host is configuration, never a literal: LEAK_FINDER_REMOTE_HOST,
# else the first line of <AUX_OPS_DIR>/leak-finder/remote-host. Without either
# the script fails closed (exit 2) instead of quietly running the 2M-case
# probe on this Mac; --local is the explicit way to run it here. A host that
# is configured but unreachable (the ssh probe fails) still falls back to
# mac-build.sh on this Mac, in the same clean worktree, which is deleted
# afterwards. The slot keeps its build cache; local temp files are deleted.
# A build host the owner has switched off (an off-switch file in the tools
# dir) is not usable either, though ssh still answers: the probe then runs
# here too. Not scheduled here: the maintainer owns the job.
#
# Environment (all optional):
#   KERNEL_REPO             a checkout of auxesis-privacy-kernel to probe;
#                            when unset, the script clones the public repo
#                            into its temp dir
#   AUX_OPS_DIR             the machine's own tools dir: it holds
#                            scripts/remote-build.sh, scripts/mac-build.sh and
#                            leak-finder/remote-host; unset by default
#   LEAK_FINDER_OUT_DIR     where the report goes (default: the report dir
#                            under AUX_OPS_DIR, else the user's cache)
#   LEAK_FINDER_DATE        the <date> stamp in the file names (default: today)
#   LEAK_FINDER_REMOTE_HOST the ssh host of the build server (the one the
#                            remote build wrapper builds on); without it the
#                            first line of <AUX_OPS_DIR>/leak-finder/remote-host
#                            is read; without either the script fails closed
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # Refuse a contradictory sandbox HOME

usage() {
  cat <<'USAGE'
usage: scripts/leak-finder.sh [--ref <git ref>] [--cases <n>] [--slot <name>] [--local]
       scripts/leak-finder.sh --help

Runs the ignored `nightly` leak-finder test
(qa/privacy-eval/tests/leak_finder.rs) of a clean checkout of <ref> in the
privacy kernel repository (default: the commit Cargo.lock pins) in release,
then writes <date>.json and <date>.md.

The probe runs on the configured build host, through the machine's remote
build wrapper. The host comes from LEAK_FINDER_REMOTE_HOST, else from the
first line of <AUX_OPS_DIR>/leak-finder/remote-host. Without either the script
fails closed with exit 2: it does not run the probe on this Mac by itself.
Pass --local to run it here on purpose; a host that is configured but
unreachable also falls back to this Mac, through the local build wrapper, and
so does a host the owner switched off (an off-switch file in the tools dir),
even though ssh still answers it. The checkout is deleted afterwards.

  --ref <git ref>   the ref to probe (default: the commit Cargo.lock pins)
  --cases <n>       the case count of the run (default: the file's own)
  --slot <name>     the remote build slot (default: leak-finder)
  --local           run the probe on this Mac, without a build host

Environment:
  KERNEL_REPO             a checkout of auxesis-privacy-kernel (default: clone
                           the public repository into the temp dir)
  AUX_OPS_DIR             the machine's own tools dir (default: unset)
  LEAK_FINDER_OUT_DIR     report directory (default: the report dir under
                           AUX_OPS_DIR, else the user's cache)
  LEAK_FINDER_DATE        date stamp in the file names (default: today)
  LEAK_FINDER_REMOTE_HOST  ssh host of the build server (default: the first
                           line of <AUX_OPS_DIR>/leak-finder/remote-host)
USAGE
}

ref=""
cases=""
slot=leak-finder
run_local=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) [[ $# -ge 2 ]] || { echo "--ref needs a value" >&2; exit 2; }; ref="$2"; shift 2 ;;
    --cases) [[ $# -ge 2 ]] || { echo "--cases needs a value" >&2; exit 2; }; cases="$2"; shift 2 ;;
    --slot) [[ $# -ge 2 ]] || { echo "--slot needs a value" >&2; exit 2; }; slot="$2"; shift 2 ;;
    --local) run_local=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -z "$cases" || "$cases" =~ ^[1-9][0-9]*$ ]] || { echo "--cases must be a positive number" >&2; exit 2; }

# The kernel commit the app pins, read from Cargo.lock: the git source line
# of the kernel crates ends in #<commit>. Reading it here keeps the probe on
# the code the app actually builds, whatever the kernel tags afterwards.
# --ref overrides it.
kernel_commit_from_lock() {
  local lock
  lock="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/Cargo.lock"
  [[ -f "$lock" ]] || return 0
  grep -m1 'auxesis-privacy-kernel' "$lock" | sed -n 's/.*#\([0-9a-f]\{40\}\).*/\1/p'
}
if [[ -z "$ref" ]]; then
  ref="$(kernel_commit_from_lock)"
  [[ -n "$ref" ]] || { echo "leak-finder: no kernel commit in Cargo.lock; pass --ref <commit>" >&2; exit 2; }
fi

# The probe lives in the kernel repository, not in this app tree. KERNEL_REPO
# names a checkout to probe; without it the script clones the public repo into
# its temp dir. The app's Cargo.lock pins the same commit this defaults to.
kernel_repo="${KERNEL_REPO:-}"
# The machine's own tools dir holds the build wrappers and the host file; the
# report directory falls back to the user's cache. No path of one machine is
# written down here: AUX_OPS_DIR is configuration, unset by default.
ops_dir="${AUX_OPS_DIR:-}"
remote_build="${ops_dir:+$ops_dir/scripts/remote-build.sh}"
mac_build="${MAC_BUILD:-${ops_dir:+$ops_dir/scripts/mac-build.sh}}"
out_dir="${LEAK_FINDER_OUT_DIR:-${ops_dir:+$ops_dir/leak-finder}}"
[[ -n "$out_dir" ]] || out_dir="${XDG_CACHE_HOME:-$HOME/Library/Caches}/auxesis/leak-finder"
day="${LEAK_FINDER_DATE:-$(date +%F)}"
[[ "$day" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "LEAK_FINDER_DATE must be YYYY-MM-DD" >&2; exit 2; }
# The build host is configuration, not a literal: the environment variable
# first, else the first line of <AUX_OPS_DIR>/leak-finder/remote-host. Without
# a host the script fails closed, so the 2M-case nightly never runs on this
# Mac by surprise; --local is the explicit way to run it here.
host_file="${ops_dir:+$ops_dir/leak-finder/remote-host}"
remote_host="${LEAK_FINDER_REMOTE_HOST:-}"
if [[ -z "$remote_host" && -f "$host_file" ]]; then
  remote_host="$(head -n 1 "$host_file" 2>/dev/null | tr -d '[:space:]' || true)"
fi
if [[ -z "$remote_host" && "$run_local" -eq 0 ]]; then
  echo "leak-finder: no build host (set LEAK_FINDER_REMOTE_HOST, or point AUX_OPS_DIR at a dir with leak-finder/remote-host); pass --local to run on this Mac" >&2
  exit 2
fi

# The owner switches a build host off with a file in the machine's own tools
# dir: <host>-off, where <host> is the configured host without its dashes, or
# the part before its first dash. The ssh probe still answers then, but the
# remote build wrapper refuses to run, so the host is not usable and the
# probe belongs on this Mac. The name comes from the configured host: no path
# of one machine is written down here.
off_file=""
host_off_file() {
  off_file=""
  [[ -n "$ops_dir" && -n "$remote_host" ]] || return 1
  local candidate
  for candidate in "$ops_dir/${remote_host//-/}-off" "$ops_dir/${remote_host%%-*}-off"; do
    if [[ -f "$candidate" ]]; then
      off_file="$candidate"
      return 0
    fi
  done
  return 1
}

# The remote host first, when one is configured: a reachable server keeps the
# 2M-case run off this Mac. When it is unreachable, or the owner switched it
# off, the same test runs here, through mac-build.sh.
remote_up() {
  [[ -n "$remote_host" ]] || return 1
  # A host the owner switched off is not usable, whatever ssh answers.
  if host_off_file; then
    return 1
  fi
  ssh -o ConnectTimeout=8 -o BatchMode=yes "root@$remote_host" true >/dev/null 2>&1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/leak-finder.XXXXXX")"
cleanup() {
  git -C "$kernel_repo" worktree remove --force "$tmp/wt" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

if [[ -z "$kernel_repo" ]]; then
  kernel_repo="$tmp/kernel"
  git clone -q https://github.com/Diclean/auxesis-privacy-kernel "$kernel_repo"
fi
git -C "$kernel_repo" fetch -q origin
rev="$(git -C "$kernel_repo" rev-parse --verify "$ref^{commit}")"

git -C "$kernel_repo" worktree add -q --detach "$tmp/wt" "$rev"
{
  echo "date $day"
  echo "rev ${rev:0:12}"
  [[ -z "$cases" ]] || echo "cases $cases"
} >"$tmp/wt/qa/privacy-eval/leak-finder.override"

run_failed() {
  grep -E '^(error|test result|REMOTE_STATUS)|panicked' "$tmp/run.log" | tail -n 20 >&2
  echo "leak-finder: the $1 run failed" >&2
  exit 1
}

echo "leak-finder: $ref (${rev:0:12}) on slot $slot"
if [[ "$run_local" -eq 0 ]] && [[ -x "$remote_build" ]] && remote_up; then
  echo "leak-finder: the build host is reachable, running the probe there"
  (cd "$tmp/wt" && REMOTE_BUILD_TIMEOUT=45m "$remote_build" "$slot" test --release \
    -p privacy-eval --no-default-features --test leak_finder \
    -- --ignored --exact nightly --nocapture) >"$tmp/run.log" 2>&1 || run_failed remote
else
  # No build host: the probe runs on this Mac. The shared build wrapper when
  # the machine configures one, else plain cargo. The no-host path (no host
  # and no --local) already failed closed above.
  local_build=(cargo)
  if [[ -n "$mac_build" && -x "$mac_build" ]]; then local_build=("$mac_build"); fi
  if [[ "$run_local" -eq 1 ]]; then
    echo "leak-finder: running the probe on this Mac (--local)"
  elif [[ -n "$off_file" ]]; then
    # remote_up found the off-switch file and refused the host.
    echo "leak-finder: the build host is switched off ($off_file), running the probe on this Mac"
  else
    echo "leak-finder: no build host is reachable, running the probe on this Mac"
  fi
  (cd "$tmp/wt" && "${local_build[@]}" test --release \
    -p privacy-eval --no-default-features --test leak_finder \
    -- --ignored --exact nightly --nocapture) >"$tmp/run.log" 2>&1 || run_failed local
fi

mkdir -p "$out_dir"
sed -n '/^LEAK-FINDER-JSON-BEGIN$/,/^LEAK-FINDER-JSON-END$/p' "$tmp/run.log" | sed '1d;$d' >"$tmp/report.json"
sed -n '/^LEAK-FINDER-MD-BEGIN$/,/^LEAK-FINDER-MD-END$/p' "$tmp/run.log" | sed '1d;$d' >"$tmp/report.md"
[[ -s "$tmp/report.json" && -s "$tmp/report.md" ]] || { echo "leak-finder: no report in the run output" >&2; exit 1; }
mv "$tmp/report.json" "$out_dir/$day.json"
mv "$tmp/report.md" "$out_dir/$day.md"
echo "leak-finder: wrote $out_dir/$day.json and $out_dir/$day.md"
