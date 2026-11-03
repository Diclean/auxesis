#!/usr/bin/env bash
# Tests for scripts/leak-finder.sh: the script parses, --help prints the usage
# and exits 0, and a bad option or a bad case count is refused with exit 2.
# Without a build host it fails closed with exit 2 instead of running the
# probe on this Mac; --local is the explicit way to run it here. Nothing here
# reaches the network, the server or the report directory: every case exits
# before the probe starts. Bash and standard tools only.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd -P)"
root="$(cd "$here/.." && pwd -P)"
finder="$here/leak-finder.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-leak-finder-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

# run_finder <args...>: sets $rc and $out.
run_finder() {
  set +e
  out="$(env -i PATH="$PATH" HOME="$tmp/home" LEAK_FINDER_OUT_DIR="$tmp/out" "$finder" "$@" 2>&1)"
  rc=$?
  set -e
}

# A stub `git` that never reaches the network: it answers the local calls
# the script makes (the repo root, the fetch, the worktree) and creates the
# worktree, so the script goes on to the build. A stub `cargo` records the
# build call and fails: the probe itself never runs here, but the script
# reaches the build, and the build it calls is what the test asserts.
mkdir -p "$tmp/bin"
cat >"$tmp/bin/git" <<STUB
#!/bin/sh
case "\$*" in
  *rev-parse*) echo "$root" ;;
  *fetch*) exit 0 ;;
  *worktree*)
    prev=""
    for a in "\$@"; do
      if [ "\$prev" = "--detach" ]; then mkdir -p "\$a/kernel/qa/privacy-eval"; fi
      prev="\$a"
    done
    exit 0 ;;
esac
exit 0
STUB
chmod +x "$tmp/bin/git"
cat >"$tmp/bin/cargo" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >>"$tmp/cargo.calls"
exit 1
STUB
chmod +x "$tmp/bin/cargo"
# A stub `ssh` that answers like a reachable build host: the script asks ssh
# only whether the host is up. The stub never reaches the network.
cat >"$tmp/bin/ssh" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >>"$tmp/ssh.calls"
exit 0
STUB
chmod +x "$tmp/bin/ssh"
# run_finder_stubbed <args...>: sets $rc and $out. STUB_OPS_DIR is the machine's
# own tools dir for this call (empty = none): the test never inherits the
# machine's setting.
run_finder_stubbed() {
  set +e
  out="$(env -i PATH="$tmp/bin:$PATH" HOME="$tmp/home" LEAK_FINDER_OUT_DIR="$tmp/out" AUX_OPS_DIR="${STUB_OPS_DIR:-}" "$finder" "$@" 2>&1)"
  rc=$?
  set -e
}

# 1. The script parses.
if bash -n "$finder"; then ok "bash -n"; else bad "bash -n"; fi

# 2. It is executable.
if [[ -x "$finder" ]]; then ok "executable"; else bad "executable"; fi

# 3. --help prints the usage and exits 0.
run_finder --help
if [[ "$rc" -eq 0 ]]; then ok "--help exits 0"; else bad "--help exits 0 (got $rc)"; fi
case "$out" in
  *"usage:"*) ok "--help prints the usage" ;;
  *) bad "--help prints the usage" ;;
esac
case "$out" in
  *"--ref"*"--cases"*"--slot"*) ok "--help lists the options" ;;
  *) bad "--help lists the options" ;;
esac

# 4. -h is the same as --help.
run_finder -h
if [[ "$rc" -eq 0 && "$out" == *"usage:"* ]]; then ok "-h exits 0"; else bad "-h exits 0 (got $rc)"; fi

# 5. An unknown option is refused with exit 2.
run_finder --nope
if [[ "$rc" -eq 2 ]]; then ok "unknown option exits 2"; else bad "unknown option exits 2 (got $rc)"; fi

# 6. A missing value is refused with exit 2.
run_finder --cases
if [[ "$rc" -eq 2 ]]; then ok "--cases without a value exits 2"; else bad "--cases without a value exits 2 (got $rc)"; fi

# 7. A bad case count is refused with exit 2.
run_finder --cases 0
if [[ "$rc" -eq 2 ]]; then ok "--cases 0 exits 2"; else bad "--cases 0 exits 2 (got $rc)"; fi
run_finder --cases abc
if [[ "$rc" -eq 2 ]]; then ok "--cases abc exits 2"; else bad "--cases abc exits 2 (got $rc)"; fi

# 8. None of the cases above wrote a report or a worktree.
if [[ ! -e "$tmp/out" ]]; then ok "no report directory created"; else bad "no report directory created"; fi
if [[ ! -e "$root/kernel/qa/privacy-eval/leak-finder.override" ]]; then
  ok "no override file in the checkout"
else
  bad "no override file in the checkout"
fi

# 9. Without a build host the script fails closed: no host in the
#    environment, none in the tools dir, no --local.
run_finder
if [[ "$rc" -eq 2 ]]; then ok "no build host exits 2"; else bad "no build host exits 2 (got $rc)"; fi
case "$out" in
  *"leak-finder: no build host"*) ok "no build host says what is missing" ;;
  *) bad "no build host says what is missing" ;;
esac
case "$out" in
  *"--local"*) ok "no build host points at --local" ;;
  *) bad "no build host points at --local" ;;
esac

# 10. --local runs on this Mac on purpose: the gate is passed. The stub git
#     and the stub cargo stop the script at the build, so nothing reaches
#     the network and no probe runs here.
run_finder_stubbed --local
case "$out" in
  *"no build host"*) bad "--local does not fail closed" ;;
  *) ok "--local does not fail closed" ;;
esac

# 11. The host file is the second source of the host: with it, the gate is
#     passed too. The file lives in the machine's own tools dir (AUX_OPS_DIR),
#     never in a fixed path.
mkdir -p "$tmp/home/ops/leak-finder"
printf 'build-host.example\n' >"$tmp/home/ops/leak-finder/remote-host"
STUB_OPS_DIR="$tmp/home/ops" run_finder_stubbed
case "$out" in
  *"leak-finder: no build host (set"*) bad "the host file does not fail closed" ;;
  *) ok "the host file does not fail closed" ;;
esac
rm -f "$tmp/home/ops/leak-finder/remote-host"
STUB_OPS_DIR=""

# 12. With no build wrapper configured (no AUX_OPS_DIR, no MAC_BUILD), --local
#     falls back to plain cargo: the probe reaches the build and cargo is what
#     runs. It must never call an empty command, and the no-host path stays
#     closed.
rm -f "$tmp/cargo.calls"
STUB_OPS_DIR="" run_finder_stubbed --local
if [[ "$rc" -eq 1 ]]; then
  ok "--local reaches the build (exit 1: the stub build failed)"
else
  bad "--local reaches the build (got $rc, wanted 1)"
fi
if [[ -s "$tmp/cargo.calls" ]] && head -n 1 "$tmp/cargo.calls" | grep -q '^test --release'; then
  ok "--local falls back to plain cargo"
else
  bad "--local falls back to plain cargo (calls: $(cat "$tmp/cargo.calls" 2>/dev/null || echo none))"
fi
case "$out" in
  *"wrapper is not configured"*) bad "--local refuses without a build wrapper" ;;
  *) ok "--local does not refuse without a build wrapper" ;;
esac

# 13. With a build wrapper configured, that wrapper is the one that runs, and
#     plain cargo is left alone.
mkdir -p "$tmp/ops/scripts"
cat >"$tmp/ops/scripts/mac-build.sh" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >>"$tmp/wrapper.calls"
exit 1
STUB
chmod +x "$tmp/ops/scripts/mac-build.sh"
rm -f "$tmp/cargo.calls" "$tmp/wrapper.calls"
STUB_OPS_DIR="$tmp/ops" run_finder_stubbed --local
if [[ -s "$tmp/wrapper.calls" ]] && head -n 1 "$tmp/wrapper.calls" | grep -q '^test --release'; then
  ok "a configured build wrapper is used"
else
  bad "a configured build wrapper is used (calls: $(cat "$tmp/wrapper.calls" 2>/dev/null || echo none))"
fi
if [[ ! -s "$tmp/cargo.calls" ]]; then
  ok "plain cargo is not called when a wrapper is configured"
else
  bad "plain cargo is not called when a wrapper is configured (calls: $(cat "$tmp/cargo.calls"))"
fi

# 14. The build host is switched off: the owner leaves an off-switch file in
#     the machine's own tools dir. ssh still answers then, but the host is
#     not usable, so the probe must run on this Mac and the remote build
#     wrapper must never be called. The off file is named after the host:
#     <host without its dashes>-off, or the part before its first dash.
#     The host here is a fictional one: no machine name is written down.
host="build-server.example"
mkdir -p "$tmp/ops-off/scripts" "$tmp/ops-off/leak-finder"
printf '%s\n' "$host" >"$tmp/ops-off/leak-finder/remote-host"
cat >"$tmp/ops-off/scripts/remote-build.sh" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >>"$tmp/remote.calls"
exit 1
STUB
cat >"$tmp/ops-off/scripts/mac-build.sh" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >>"$tmp/mac.calls"
exit 1
STUB
chmod +x "$tmp/ops-off/scripts/remote-build.sh" "$tmp/ops-off/scripts/mac-build.sh"

# 15. Without the off file nothing changes: the host answers, so the remote
#     build wrapper is the one that runs and the local one is left alone.
rm -f "$tmp/remote.calls" "$tmp/mac.calls"
STUB_OPS_DIR="$tmp/ops-off" run_finder_stubbed
if [[ -s "$tmp/remote.calls" ]]; then
  ok "without the off file the remote wrapper is called"
else
  bad "without the off file the remote wrapper is called (calls: $(cat "$tmp/remote.calls" 2>/dev/null || echo none))"
fi
if [[ ! -s "$tmp/mac.calls" ]]; then
  ok "without the off file the local wrapper is not called"
else
  bad "without the off file the local wrapper is not called (calls: $(cat "$tmp/mac.calls"))"
fi

# 16. With the off file present (<host without dashes>-off), the probe runs
#     here: the local wrapper is called, the remote one never is.
rm -f "$tmp/remote.calls" "$tmp/mac.calls"
: >"$tmp/ops-off/buildserver.example-off"
STUB_OPS_DIR="$tmp/ops-off" run_finder_stubbed
if [[ -s "$tmp/mac.calls" ]]; then
  ok "a switched-off host runs the probe on this Mac"
else
  bad "a switched-off host runs the probe on this Mac (calls: $(cat "$tmp/mac.calls" 2>/dev/null || echo none))"
fi
if [[ ! -s "$tmp/remote.calls" ]]; then
  ok "a switched-off host never calls the remote wrapper"
else
  bad "a switched-off host never calls the remote wrapper (calls: $(cat "$tmp/remote.calls"))"
fi
case "$out" in
  *"switched off"*"buildserver.example-off"*) ok "a switched-off host says so" ;;
  *) bad "a switched-off host says so" ;;
esac

# 17. The other name for the same switch: the part of the host before its
#     first dash (<host prefix>-off).
rm -f "$tmp/remote.calls" "$tmp/mac.calls" "$tmp/ops-off/buildserver.example-off"
: >"$tmp/ops-off/build-off"
STUB_OPS_DIR="$tmp/ops-off" run_finder_stubbed
if [[ -s "$tmp/mac.calls" ]] && [[ ! -s "$tmp/remote.calls" ]]; then
  ok "the host prefix off file switches the host off too"
else
  bad "the host prefix off file switches the host off too (local: $(cat "$tmp/mac.calls" 2>/dev/null || echo none), remote: $(cat "$tmp/remote.calls" 2>/dev/null || echo none))"
fi

# 18. An off file for another host does not switch this one off.
rm -f "$tmp/remote.calls" "$tmp/mac.calls" "$tmp/ops-off/build-off"
: >"$tmp/ops-off/otherhost-off"
STUB_OPS_DIR="$tmp/ops-off" run_finder_stubbed
if [[ -s "$tmp/remote.calls" ]] && [[ ! -s "$tmp/mac.calls" ]]; then
  ok "an off file for another host leaves this host alone"
else
  bad "an off file for another host leaves this host alone (local: $(cat "$tmp/mac.calls" 2>/dev/null || echo none), remote: $(cat "$tmp/remote.calls" 2>/dev/null || echo none))"
fi

# 19. The no-host path still fails closed with an off file lying around:
#     without a host there is nothing to switch off.
mkdir -p "$tmp/ops-nohost"
: >"$tmp/ops-nohost/buildserver.example-off"
rm -f "$tmp/remote.calls" "$tmp/mac.calls"
STUB_OPS_DIR="$tmp/ops-nohost" run_finder_stubbed
if [[ "$rc" -eq 2 ]]; then
  ok "no build host exits 2 with the off file present"
else
  bad "no build host exits 2 with the off file present (got $rc)"
fi

if [[ "$fail" -eq 0 ]]; then
  echo "test-leak-finder: $pass passed, 0 failed"
else
  echo "test-leak-finder: $pass passed, $fail FAILED" >&2
  exit 1
fi
