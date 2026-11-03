#!/usr/bin/env bash
# Runs one CI command under the literal sandbox from `CONTRIBUTING.md`, on the
# Mac runner (its HOME is the owner's real home).
#
#   scripts/ci-sandbox-env.sh cargo test --workspace --locked
#
# The command gets a fresh HOME, AUXESIS_HOME and TMPDIR under mktemp, the
# sandbox flags, and nothing else from the runner's environment: `env -i`
# keeps PATH, the real toolchain (CARGO_HOME, RUSTUP_HOME), the shared build
# dir and the test knobs. The temp dir is deleted on exit, including a failed
# or interrupted run. AUX_HERO_* variables are passed through for the nightly
# hero legs; their values are never printed.
#
# AUXESIS_ALLOW_KEYCHAIN is never set here: the real Keychain stays off.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

real_home="$HOME"
cargo_home="${CARGO_HOME:-$real_home/.cargo}"
rustup_home="${RUSTUP_HOME:-$real_home/.rustup}"
target_dir="${CARGO_TARGET_DIR:-$real_home/Library/Caches/auxesis-ci-target}"

# Always under /tmp, never the caller's TMPDIR: the runner's RUNNER_TEMP lives
# under the owner's home, and guard.sh refuses a sandbox HOME inside it.
sandbox="$(mktemp -d /tmp/auxesis-ci-sandbox.XXXXXX)"
# A signal must reach the EXIT trap too, so the sandbox is always removed.
trap 'rm -rf "$sandbox"' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# Names only, never values: AUX_HERO_* carries the nightly leg settings.
passthrough=()
while IFS= read -r name; do
    case "$name" in
        AUX_HERO_*) passthrough+=("$name=${!name}") ;;
    esac
done < <(compgen -e)

env -i \
    PATH="$cargo_home/bin:$PATH" \
    HOME="$sandbox" \
    AUXESIS_HOME="$sandbox/.auxesis" \
    AUXESIS_SANDBOX=1 \
    AUXESIS_API_PORT=0 \
    TMPDIR="$sandbox" \
    CARGO_HOME="$cargo_home" \
    RUSTUP_HOME="$rustup_home" \
    CARGO_TARGET_DIR="$target_dir" \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_PROFILE_TEST_DEBUG=0 \
    RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}" \
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}" \
    LANG=en_US.UTF-8 \
    TERM=dumb \
    ${passthrough[@]+"${passthrough[@]}"} \
    "$@"
