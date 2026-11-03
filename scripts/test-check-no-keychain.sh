#!/usr/bin/env bash
# Self-test for scripts/check-no-keychain.sh. A fake `cargo` records the
# environment of every run, so nothing is built or read. The test asserts each
# phase's environment: the sandboxed workspace run sets AUXESIS_SANDBOX=1 and
# AUXESIS_API_PORT=0; the unflagged runs set no AUXESIS_* variable at all, and
# `security` resolves to the shim. No run ever uses the caller's real HOME.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/aux-nokeychain-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
real_home="$(guard_real_home)"
[[ -n "$real_home" ]] || { echo "FAIL: cannot resolve the real home" >&2; exit 1; }

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# One file per cargo run, numbered in call order.
mkdir -p "$work/bin"
cat >"$work/bin/cargo" <<SH
#!/bin/sh
dir="$work/calls"
mkdir -p "\$dir"
n=\$(( \$(ls "\$dir" | wc -l) + 1 ))
{
  echo "home=\$HOME"
  echo "sandbox=\${AUXESIS_SANDBOX:-unset}"
  echo "allow_keychain=\${AUXESIS_ALLOW_KEYCHAIN:-unset}"
  echo "auxesis_home=\${AUXESIS_HOME:-unset}"
  echo "api_port=\${AUXESIS_API_PORT:-unset}"
  echo "toolchain=\${RUSTUP_TOOLCHAIN:-unset}"
  echo "security=\$(command -v security || echo none)"
  echo "args=\$*"
} >"\$dir/\$n"
SH
chmod +x "$work/bin/cargo"

# Every run: the HOME is scratch, never the real one.
assert_scratch_home() {
  local file="$1" home
  home="$(sed -n 's/^home=//p' "$file")"
  [[ -n "$home" ]] || fail "$file: no HOME recorded"
  [[ "$home" != "$real_home" ]] || fail "$file: the run used the real HOME"
  case "$home" in
    "$real_home"/*) fail "$file: the run used a path under the real HOME ($home)" ;;
  esac
}

# Every unflagged run: the Keychain opt-in and sandbox flags are absent, and the
# `security` on PATH is the shim, never /usr/bin/security.
assert_unflagged() {
  local file="$1" security
  grep -qx 'sandbox=unset' "$file" || fail "$file: the unflagged run must not set AUXESIS_SANDBOX"
  grep -qx 'allow_keychain=unset' "$file" || fail "$file: the unflagged run must not set AUXESIS_ALLOW_KEYCHAIN"
  grep -qx 'auxesis_home=unset' "$file" || fail "$file: the unflagged run must not set AUXESIS_HOME"
  grep -qx 'api_port=unset' "$file" || fail "$file: the unflagged run must not set AUXESIS_API_PORT"
  security="$(sed -n 's/^security=//p' "$file")"
  case "$security" in
    */bin/security) ;;
    *) fail "$file: security must resolve to the shim, got '$security'" ;;
  esac
}

output="$(PATH="$work/bin:$PATH" bash "$root/scripts/check-no-keychain.sh" --locked 2>&1)" \
  || fail "the run must pass when cargo passes: $output"

calls="$work/calls"
[[ "$(ls "$calls" | wc -l | tr -d ' ')" == 4 ]] || fail "expected four cargo runs (1 sandboxed, 3 unflagged), got $(ls "$calls" | wc -l | tr -d ' ')"

# Phase 1: sandboxed, the whole workspace.
first="$calls/1"
assert_scratch_home "$first"
grep -qx 'sandbox=1' "$first" || fail "the sandboxed run must set AUXESIS_SANDBOX=1"
grep -qx 'api_port=0' "$first" || fail "the sandboxed run must set AUXESIS_API_PORT=0"
grep -qx 'allow_keychain=unset' "$first" || fail "the sandboxed run must never set AUXESIS_ALLOW_KEYCHAIN"
grep -q '^auxesis_home=/' "$first" || fail "the sandboxed run must set AUXESIS_HOME under the scratch HOME"
grep -qx 'args=test --workspace --locked' "$first" || fail "the sandboxed run must test the whole workspace"

# Phase 2: unflagged, targeted to the Keychain-backend crates (lib, then bins),
# then the kernel keychain tests.
for n in 2 3 4; do
  assert_scratch_home "$calls/$n"
  assert_unflagged "$calls/$n"
done
grep -q '^args=test -p kernel-core -p aux-providers -p auxd --lib' "$calls/2" \
  || fail "the unflagged run must target the Keychain-backend library crates"
grep -q '^args=test -p aux-cli --bins' "$calls/3" \
  || fail "the unflagged run must target the aux-cli binary (vault) tests"
grep -q '^args=test -p kernel-core --test keychain_shim' "$calls/4" \
  || fail "the unflagged run must include the kernel keychain tests"

# The control is skipped, and the script says so.
grep -q 'NOTE: control skipped' <<<"$output" || fail "the skipped control must print a NOTE"

# --nextest: a fake cargo-nextest (pinned by its own hash through the
# AUX_NEXTEST_SHA256 seam) records like the fake cargo; then the doctests and the
# unchanged unflagged runs.
fake_nx="$work/nx/cargo-nextest"
mkdir -p "$work/nx"
# It also keeps a copy of the --config-file it was given.
sed '1a\
echo "nextest-bin=\$0" >>"'"$work"'/nxbin"; prev=""; for a in "\$@"; do [ "\$prev" = --config-file ] \&\& cp "\$a" "'"$work"'/nxcfg"; prev="\$a"; done' "$work/bin/cargo" >"$fake_nx"
chmod +x "$fake_nx"
fake_sha="$(shasum -a 256 "$fake_nx" | cut -d' ' -f1)"
nx_env=(AUX_NEXTEST_BIN="$fake_nx" AUX_NEXTEST_SHA256="$fake_sha")
rm -rf "$calls"
env "${nx_env[@]}" PATH="$work/bin:$PATH" bash "$root/scripts/check-no-keychain.sh" --nextest --locked >/dev/null 2>&1 \
  || fail "the --nextest run must pass when cargo passes"
[[ "$(ls "$calls" | wc -l | tr -d ' ')" == 5 ]] || fail "expected five runs with --nextest, got $(ls "$calls" | wc -l | tr -d ' ')"
grep -q '/nx/cargo-nextest$' "$work/nxbin" || fail "nextest must run from the private copy"
grep -q "^nextest-bin=$work/" "$work/nxbin" && fail "nextest must not run from its install path"
for n in 1 2; do
  assert_scratch_home "$calls/$n"
  grep -qx 'sandbox=1' "$calls/$n" || fail "the nextest-phase run $n must set AUXESIS_SANDBOX=1"
  grep -qx 'api_port=0' "$calls/$n" || fail "the nextest-phase run $n must set AUXESIS_API_PORT=0"
  grep -qx 'allow_keychain=unset' "$calls/$n" || fail "the nextest-phase run $n must never set AUXESIS_ALLOW_KEYCHAIN"
  grep -q '^security=.*/bin/security$' "$calls/$n" || fail "the nextest-phase run $n must see the shim"
done
grep -Eqx 'args=nextest run --config-file /.*/nx/nextest.toml --profile ci --ignore-default-filter --workspace --locked' "$calls/1" \
  || fail "--nextest must run the whole workspace, checked config, ci profile, no default filter: $(grep args "$calls/1")"
grep -q '^toolchain=[0-9a-z]' "$calls/1" || fail "nextest must run with the repo's RUSTUP_TOOLCHAIN"
grep -qx 'args=test --doc --workspace --locked' "$calls/2" || fail "--nextest must run the workspace doctests"
for n in 3 4 5; do
  assert_scratch_home "$calls/$n"
  assert_unflagged "$calls/$n"
done

# Refusals: each must fail before any test runs.
refused() {
  local why="$1"; shift
  rm -rf "$calls"
  local status=0 out
  out="$(env "$@" PATH="$work/bin:$PATH" bash "$root/scripts/check-no-keychain.sh" --nextest --locked 2>&1)" || status=$?
  [[ $status -ne 0 ]] || fail "$why must be refused"
  grep -q '^FAIL: ' <<<"$out" || fail "$why must print a FAIL line"
  [[ ! -e "$calls" ]] || fail "$why must be refused before any test runs"
}
# A binary that prints the right version but is not the pinned build.
printf '#!/bin/sh\necho "cargo-nextest 0.9.150"\n' >"$work/nx/impostor"
chmod +x "$work/nx/impostor"
refused "a cargo-nextest with the wrong hash" AUX_NEXTEST_BIN="$work/nx/impostor"

# The repo's nextest config has no effect: a copy of the script in a scratch
# git repo with a hostile .config/nextest.toml (escaped retries key, default
# filter, overrides) hands nextest the same generated config, byte for byte.
cp "$work/nxcfg" "$work/nxcfg.clean"
grep -qx 'retries = 0' "$work/nxcfg.clean" || fail "the generated config must set retries = 0"
grep -q 'default-filter' "$work/nxcfg.clean" && fail "the generated config must not set a default filter"
hostile="$work/hostile"
mkdir -p "$hostile/scripts/lib" "$hostile/.config"
cp "$root/scripts/check-no-keychain.sh" "$hostile/scripts/"
cp "$root/scripts/lib/guard.sh" "$hostile/scripts/lib/"
cat >"$hostile/.config/nextest.toml" <<'TOML'
[profile.ci]
"retr\u0069es" = 2
default-filter = "test(=only_this_one)"
[[profile.ci.overrides]]
filter = "all()"
retries = 5
TOML
git -C "$hostile" init -q
rm -rf "$calls" "$work/nxcfg"
(cd "$hostile" && env "${nx_env[@]}" PATH="$work/bin:$PATH" bash scripts/check-no-keychain.sh --nextest --locked >/dev/null 2>&1) \
  || fail "the --nextest run in the hostile repo must pass when cargo passes"
cmp -s "$work/nxcfg" "$work/nxcfg.clean" || fail "a repo .config/nextest.toml must not change the config nextest runs with"
grep -q "$hostile/.config" "$calls/1" && fail "nextest must never be pointed at the repo config"

# A failing cargo must fail the script, so a red suite cannot read as clean.
cat >"$work/bin/cargo" <<'SH'
#!/bin/sh
exit 101
SH
status=0
PATH="$work/bin:$PATH" bash "$root/scripts/check-no-keychain.sh" --locked >/dev/null 2>&1 || status=$?
[[ $status -ne 0 ]] || fail "a failing workspace run must fail the script"
# Only the nextest run fails (cargo passes): the script must still fail.
printf '#!/bin/sh\nexit 0\n' >"$work/bin/cargo"
printf '#!/bin/sh\nexit 100\n' >"$fake_nx"
status=0
env AUX_NEXTEST_BIN="$fake_nx" AUX_NEXTEST_SHA256="$(shasum -a 256 "$fake_nx" | cut -d' ' -f1)" \
  PATH="$work/bin:$PATH" bash "$root/scripts/check-no-keychain.sh" --nextest --locked >/dev/null 2>&1 || status=$?
[[ $status -ne 0 ]] || fail "a failing nextest run must fail the script"

echo "OK: check-no-keychain.sh runs each phase under a scratch HOME with the expected environment"
