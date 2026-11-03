#!/usr/bin/env bash
# Local pre-merge precheck — the LOCAL gate entry point (run on the Mac).
#
# Steps, in order:
#   1. scripts/check-no-secrets.sh — the secret/personal-data scan CI runs.
#   2. scripts/check-no-rich-render.sh — the shipped app keeps untrusted text
#      plain: no Markdown/HTML, no WebView, no remote image, no URL opening.
#   2b. scripts/check-mcp-catalog.sh — validates catalog/mcp-servers.toml
#      (TOML shape, enums, https provenance, recommended is read-only).
#   2c. scripts/check-egress.sh — every reqwest client in production code must
#      be documented in docs/egress.md (static, offline).
#   3. cargo deny check — BLOCKING. Any advisory/ban/licence/source finding
#      fails the gate. There is no warning-only path and no `continue-on-error`
#      here; deny.toml itself is unchanged. (The CI `deny` job is non-blocking
#      and carries `continue-on-error: true`, so this is the gate that enforces it.)
#   4. scripts/swift-gate.sh — swift build + swift test in apps/auxesis-mac.
#      Mac-only, as is the product.
#   5. Report whether the Rust cargo gates (fmt/clippy/test) are needed. Run
#      them on the Mac with cargo, or through the shared build wrapper when
#      the machine configures one ($AUX_OPS_DIR/scripts/mac-build.sh).
#
# It never touches the Keychain. The only step that may reach the network is
# `cargo deny check` fetching the RustSec advisory database on a cold cache.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

scripts/check-no-secrets.sh
scripts/check-no-rich-render.sh
scripts/check-mcp-catalog.sh
scripts/check-egress.sh

# --- 3. cargo deny: hard gate ------------------------------------------------
if ! command -v cargo-deny >/dev/null 2>&1; then
    echo "precheck: cargo-deny is not installed — the dependency-policy gate cannot be skipped." >&2
    echo "          Install it (cargo install cargo-deny --locked) or run" >&2
    echo "          'cargo deny check' on the Mac." >&2
    exit 1
fi
# A non-zero exit fails precheck: no `|| true`, no silent warning.
echo "precheck: cargo deny check (blocking)…"
cargo deny check

base="${1:-origin/main}"
changed="$(git diff --name-only "$base"...HEAD || true)"

code_changed=0
while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    case "$path" in
        *.md | docs/plans/* | docs/progress/* | docs/ui* | docs/archive/* | qa/*.md) ;;
        *) code_changed=1 ;;
    esac
done <<<"$changed"

# --- 4. Swift gate: LOCAL macOS only -----------------------------------------
# Run it for any code change, not just Swift edits: the hole this closes is
# that no gate ever ran the Swift tests. A docs-only diff skips it.
if [[ "$code_changed" -eq 1 ]]; then
    scripts/swift-gate.sh
else
    echo "precheck: docs-only diff vs $base — Swift gate skipped."
fi

# --- 5. Rust cargo gates (run on the Mac) -----------------------------------
if [[ "$code_changed" -eq 0 ]]; then
    echo "precheck: docs-only diff vs $base — no cargo gates needed."
else
    echo "precheck: code changed vs $base — run the cargo gates on the Mac:"
    echo "  cargo fmt --all -- --check"
    echo "  cargo clippy --workspace --all-targets -- -D warnings"
    echo "  cargo test --workspace"
    echo "  With a shared build lock, run them through \$AUX_OPS_DIR/scripts/mac-build.sh."
    echo "  Retry a build if the wrapper exits 75."
fi
