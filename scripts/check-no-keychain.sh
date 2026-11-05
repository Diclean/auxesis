#!/usr/bin/env bash
# Fail if any test spawns the macOS `security` binary.
#
# A fake `security` earlier in PATH records every invocation; the marker file
# must stay absent. Every phase runs under a scratch HOME, never the caller's
# real HOME (on the Mac CI runner that is the owner's account):
#
#   1. sandboxed (`AUXESIS_SANDBOX=1`, `AUXESIS_HOME`, `AUXESIS_API_PORT=0`,
#      `env -i`): the whole workspace suite, the current contract. This is the
#      CI test step on the Mac. Test processes use a scratch HOME, never the
#      owner's real Keychain.
#   2. unflagged (no `AUXESIS_*` variable at all, `env -i`): the default-deny repro.
#      With no opt-in, the default-deny path must not spawn `security`. Targeted
#      to the crates that own a Keychain backend (aux-providers, aux-cli, auxd),
#      so CI does not start the daemon tests on the default port.
#   3. control: not run. `keychain_allowed()` only passes when HOME is the OS
#      account's home, so the opt-in cannot reach the shim from a scratch HOME,
#      and under the real HOME it would touch the owner's Keychain. A NOTE says so.
#
# Usage: scripts/check-no-keychain.sh [--nextest] [extra cargo-test args]
# --nextest runs phase 1 with `cargo nextest run --profile ci`
# (a config this script writes), so test binaries and tests run in parallel, then
# `cargo test --doc` for the doctests nextest skips; same sandbox, same tests.
# Without cargo-nextest installed it falls back to `cargo test` with a NOTE.
# The binary must match NEXTEST_SHA256 (the pinned `cargo install --locked`
# build); it is copied into this run's private temp dir, hashed and run from
# there, so a swap after the check cannot run. The nextest config is never read
# from the repo: the script writes a fixed one into the same private dir and
# passes it with --config-file (which replaces .config/nextest.toml), plus
# --ignore-default-filter. AUX_NEXTEST_BIN and AUX_NEXTEST_SHA256 are self-test seams.
# AUX_TEST_SCOPE (default `--workspace`) narrows phase 1 to `-p` packages for
# focused runs. PR CI uses the full workspace. Phase 2 is never narrowed.
set -euo pipefail

# cargo-nextest 0.9.150: the aarch64-apple-darwin `cargo install --locked` build
# (maintainer Mac), then the official universal-apple-darwin release binary that
# CI downloads (tarball sha256 82a759b4...c3c301a, checked in ci.yml).
NEXTEST_SHA256="6e256a8d8d9d0c897e5027deefe7483fb0a98b15ccbe073eee1f95bb6eb068a4"
NEXTEST_RELEASE_SHA256="aad9d409cd2f0a81fcaed49d7672a133254179458436c1e957505e4a11655329"

use_nextest=0
if [[ "${1:-}" == "--nextest" ]]; then
    use_nextest=1
    shift
fi

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # Refuse a contradictory sandbox HOME

root="$(git rev-parse --show-toplevel)"
original_home="$HOME"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/aux-nokeychain.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

shim="$tmp/bin"
marker="$tmp/invoked"
mkdir -p "$shim"
cat > "$shim/security" <<EOF
#!/bin/sh
echo "invoked: \$*" >> "$marker"
exit 44
EOF
chmod +x "$shim/security"

check_marker() {
    if [[ -e "$marker" ]]; then
        echo "FAIL: $1 spawned the security shim:" >&2
        cat "$marker" >&2
        exit 1
    fi
}

# Keep the toolchain reachable when HOME moves to a scratch directory.
export RUSTUP_HOME="${RUSTUP_HOME:-$original_home/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$original_home/.cargo}"

cd "$root"

# Phase 1: sandboxed, with a minimal environment (`env -i`). AUX_TEST_SCOPE is
# split into words on purpose (several `-p` flags).
sandbox_home="$tmp/h"
mkdir -p "$sandbox_home"
nextest_env=()
if (( use_nextest )); then
    nextest_src="${AUX_NEXTEST_BIN:-$CARGO_HOME/bin/cargo-nextest}"
    if [[ ! -e "$nextest_src" ]]; then
        echo "NOTE: cargo-nextest is not installed at $nextest_src; phase 1 falls back to cargo test"
        use_nextest=0
    else
        mkdir -p "$tmp/nx"
        nextest_bin="$tmp/nx/cargo-nextest"
        nextest_config="$tmp/nx/nextest.toml"
        cp "$nextest_src" "$nextest_bin"
        # Fixed content, never from the repo, so a PR cannot add retries or filters.
        cat >"$nextest_config" <<'TOML'
[profile.ci]
# Hosted macos-15 runners have 3 cores; most tests wait on I/O and child processes.
test-threads = 6
fail-fast = false
# A flaky test must show red, not pass on a second try.
retries = 0
# Flag a test after 60 s; kill a hung one after 15 periods (15 min), as a failure.
slow-timeout = { period = "60s", terminate-after = 15 }
final-status-level = "slow"

# Tests that assert wall-clock time run alone and first: under parallel load
# they failed on the clock, not on behaviour (about 60 s serial).
[[profile.ci.overrides]]
filter = 'test(/linear|scales|_seconds|times_out|expired|grace|approval_timeout/)'
threads-required = "num-test-threads"
priority = 100

# Bomb and resource-limit tests each run alone: process limits count every
# process the user runs, and a fork bomb, a 600 MB allocation or a CPU spin
# starves its neighbours. threads-required takes every test slot; the group
# also keeps them from overlapping each other.
[test-groups]
resource-limits = { max-threads = 1 }

[[profile.ci.overrides]]
filter = 'test(/fork_bomb|process_bomb|memory_bomb|_limit_stops_|memory_watchdog/)'
test-group = "resource-limits"
threads-required = "num-test-threads"

# The longest tests (property tests, about 3-5 min each) start next, so they
# do not form a tail at the end. nextest refuses a binary() name that matches
# no test binary: keep this list to binaries in this workspace.
[[profile.ci.overrides]]
filter = 'binary(crm_property) | binary(crm_promote_property)'
priority = 50
TOML
        chmod 0500 "$nextest_bin"
        got="$(shasum -a 256 "$nextest_bin" | cut -d' ' -f1)"
        if [[ -n "${AUX_NEXTEST_SHA256:-}" ]]; then
            allowed=("$AUX_NEXTEST_SHA256")
        else
            allowed=("$NEXTEST_SHA256" "$NEXTEST_RELEASE_SHA256")
        fi
        if [[ " ${allowed[*]} " != *" $got "* ]]; then
            echo "FAIL: $nextest_src has SHA-256 $got, not the pinned cargo-nextest; reinstall with: cargo install cargo-nextest --locked --version 0.9.150" >&2
            exit 1
        fi
        # Run by path, nextest skips the rustup proxy that sets RUSTUP_TOOLCHAIN
        # for `cargo test`; tests that spawn cargo (registry_thread_local_drop)
        # then picked another rustc. Pin the repo toolchain explicitly.
        toolchain="$(rustup show active-toolchain 2>/dev/null | cut -d' ' -f1 || true)"
        [[ -n "$toolchain" ]] && nextest_env=(RUSTUP_TOOLCHAIN="$toolchain")
    fi
fi
sandbox_env=(
    HOME="$sandbox_home"
    AUXESIS_HOME="$sandbox_home/.auxesis"
    AUXESIS_SANDBOX=1
    AUXESIS_API_PORT=0
    PATH="$shim:$PATH"
    CARGO_HOME="$CARGO_HOME"
    RUSTUP_HOME="$RUSTUP_HOME"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
    CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
    CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
    CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}"
    RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"
    LANG=en_US.UTF-8
    TERM=dumb
)
phase1_start=$SECONDS
# shellcheck disable=SC2086
if (( use_nextest )); then
    env -i "${sandbox_env[@]}" ${nextest_env[@]+"${nextest_env[@]}"} \
        "$nextest_bin" nextest run --config-file "$nextest_config" --profile ci \
        --ignore-default-filter ${AUX_TEST_SCOPE:---workspace} "$@"
    env -i "${sandbox_env[@]}" \
        cargo test --doc ${AUX_TEST_SCOPE:---workspace} "$@"
else
    env -i "${sandbox_env[@]}" \
        cargo test ${AUX_TEST_SCOPE:---workspace} "$@"
fi
echo "TIME: the sandboxed workspace run took $(( SECONDS - phase1_start )) s"
check_marker "the sandboxed workspace run"
echo "OK: the sandboxed workspace run did not spawn the security binary"

# Phase 2: unflagged. No AUXESIS_* variable is set, so the default-deny path is
# what runs. The shim is first in PATH; cargo still resolves from the caller's PATH.
rm -f "$marker"
unflagged_home="$tmp/u"
mkdir -p "$unflagged_home"
unflagged_env=(
    HOME="$unflagged_home"
    PATH="$shim:$PATH"
    CARGO_HOME="$CARGO_HOME"
    RUSTUP_HOME="$RUSTUP_HOME"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
    CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
    CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
    CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}"
    RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"
    LANG=en_US.UTF-8
    TERM=dumb
)
env -i "${unflagged_env[@]}" \
    cargo test -p aux-providers -p auxd --lib "$@"
env -i "${unflagged_env[@]}" \
    cargo test -p aux-cli --bins "$@"
check_marker "the unflagged Keychain-crate run"
echo "OK: the unflagged Keychain-crate run did not spawn the security binary"

# Phase 3: control, skipped. keychain_allowed() only passes when HOME is the OS
# account's home, so with the opt-in a scratch HOME is refused before the shim
# is reached. Under the real HOME the control would touch the owner's Keychain.
echo "NOTE: control skipped: the Keychain opt-in needs the OS account home, so the shim is unreachable from a scratch HOME; CI never runs under the real HOME"

echo "OK: no test spawned the security binary without the explicit opt-in"
