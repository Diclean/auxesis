#!/usr/bin/env bash
# One fast local gate, run before a push (scripts/install-hooks.sh points
# .githooks/pre-push at it). Order: fmt, clippy on the touched crates, the
# offline scanners. Stops at the first failure with one RED line.
#
#   scripts/gate-fast.sh               the full fast gate
#   scripts/gate-fast.sh --no-clippy   docs-only push; refused if .rs/.toml/.swift/.lock changed
#
# Cargo runs through the shared build wrapper when the machine configures one
# (AUX_OPS_DIR points at the tools dir, MAC_BUILD at the wrapper itself): one
# build at a time, warm shared target. Else plain cargo. Emergencies only:
# git push --no-verify.
set -euo pipefail
source "$(git rev-parse --show-toplevel)/scripts/lib/guard.sh"  # J-02 round 7: refuse a contradictory sandbox HOME

cd "$(git rev-parse --show-toplevel)"
start=$SECONDS

# The shared build wrapper, when the machine configures one (AUX_OPS_DIR).
mac_build="${MAC_BUILD:-${AUX_OPS_DIR:+$AUX_OPS_DIR/scripts/mac-build.sh}}"

no_clippy=0
case "${1:-}" in
    "") ;;
    --no-clippy) no_clippy=1 ;;
    *) echo "gate-fast: unknown argument '$1' (only --no-clippy)" >&2; exit 2 ;;
esac

# Files changed against the merge-base with origin/main: committed, staged,
# unstaged and untracked. Without that base nothing can be scoped, so fail.
base="$(git merge-base origin/main HEAD 2>/dev/null || true)"
if [[ -z "$base" ]]; then
    echo "gate-fast: RED at setup: no merge-base with origin/main (run: git fetch origin main)" >&2
    exit 1
fi
changed="$(git diff --name-only "$base"; git ls-files --others --exclude-standard)"

if (( no_clippy )) && grep -qE '\.(rs|toml|swift|lock)$' <<<"$changed"; then
    echo "gate-fast: --no-clippy refused: .rs/.toml/.swift/.lock files changed" >&2
    exit 2
fi

run_cargo() {
    if [[ -n "$mac_build" && -x "$mac_build" ]]; then
        "$mac_build" "$@"
    else
        cargo "$@"
    fi
}

# One step: its name, its own output, and one RED line when it fails.
step() {
    local name="$1"
    shift
    echo "gate-fast: $name"
    if ! "$@"; then
        echo "gate-fast: RED at $name" >&2
        exit 1
    fi
}

# A step whose script is not in this tree is skipped, never failed: the harness
# of the Mac app lives in the private tree and the public export leaves it out.
harness_step() { # harness_step <name> <script>
    local name="$1" script="$2"
    if [ ! -f "$script" ]; then
        echo "gate-fast: $name — skipped: private harness not in this tree"
        return 0
    fi
    step "$name" "$script"
}

# Static keychain guard. check-no-keychain.sh runs the whole test suite under
# a scratch HOME in CI (the Mac runner), so it stays a CI step too. Only the
# default-deny backends (aux-cli vault, aux-providers key) may name the
# `security` binary.
check_keychain() {
    local hits
    local paths=(':(glob)crates/**/*.rs' ':(glob)crates/**/Cargo.toml')
    hits="$(git grep --untracked -nE '"security"|/usr/bin/security|(find|add|set|delete)-(generic|internet)-password|dump-keychain|list-keychains|unlock-keychain|SecItem[A-Za-z0-9_]*|SecKeychain[A-Za-z0-9_]*|security[-_]framework|Security\.framework' -- "${paths[@]}" \
        | grep -vE '^(crates/(aux-cli/src/vault|aux-providers/src/key)\.rs):' || true)"
    if [[ -n "$hits" ]]; then
        echo "$hits" >&2
        echo "keychain: the security binary is called outside the default-deny backends (lines above)" >&2
        return 1
    fi
}

# Clippy scope: the packages of the touched crates, or the whole workspace when
# a root manifest/toolchain changed or no touched file maps to a crate.
whole=0
if grep -qxE 'Cargo\.toml|Cargo\.lock|rust-toolchain(\.toml)?|\.cargo/config\.toml' <<<"$changed"; then
    whole=1
fi
# Package name of each touched crate (crates/<dir>/Cargo.toml [package] name).
# A function, not a $( ) block: bash 3.2 (the Mac default) cannot parse case
# patterns inside command substitution.
map_packages() {
    local f dir pkg
    while IFS= read -r f; do
        case "$f" in
            crates/*/*)
                dir="${f#crates/}"
                dir="${dir%%/*}"
                pkg="$(awk -F'"' '/^name[[:space:]]*=/ { print $2; exit }' "crates/$dir/Cargo.toml" 2>/dev/null || true)"
                if [[ -n "$pkg" ]]; then echo "$pkg"; fi
                ;;
        esac
    done <<<"$1"
}
mapped="$(map_packages "$changed" | sort -u)"
scope=(--workspace)
if (( ! whole )) && [[ -n "$mapped" ]]; then
    scope=()
    while IFS= read -r p; do scope+=(-p "$p"); done <<<"$mapped"
fi

step fmt run_cargo fmt --all -- --check
step swift-test-discovery scripts/check-swift-test-discovery.sh
step step-tool-ids python3 -I scripts/check-step-tool-ids.py --check
step app-icon scripts/test-app-icon.sh
if (( no_clippy )); then
    echo "gate-fast: clippy skipped (--no-clippy)"
else
    step clippy run_cargo clippy "${scope[@]}" --all-targets --locked -- -D warnings
fi
step egress scripts/check-egress.sh
step mcp-catalog scripts/check-mcp-catalog.sh
step keychain check_keychain
step secrets scripts/check-no-secrets.sh
step gitleaks-config scripts/test-gitleaks-config.sh
step personal-data scripts/check-personal-data.sh
step test-sandbox scripts/check-test-sandbox.sh
# The build lock's release path (CI-LOCK-RMDIR): the workflows call this
# script, so the fast gate proves an already-released lock, another job's lock
# and an unmarked lock never turn a green run red.
step ci-build-lock scripts/test-ci-build-lock.sh
# The harness that judges the app: its own self-tests, headless (no app, no
# permission, no network). A harness that rots judges nothing, so its proof is
# part of the gate. Both scripts live in the private tree: a public tree skips.
harness_step sim-use scripts/test-sim-use.sh
harness_step sim-human scripts/test-sim-human.sh
# The release signing path (BUILD-NUMBER-P3): the signer is built in a scratch
# dir of its own and signs with a throwaway key, so no signing identity and
# no Keychain is needed. It runs in about 20 s, which fits the fast gate.
# The packaging self-test (scripts/test-package-mac.sh) builds the app and
# the daemon: it belongs to the CI check job, not here.
step sign-release scripts/test-sign-release.sh
echo "gate-fast: GREEN in $((SECONDS - start))s"
