#!/usr/bin/env bash
# Self-test for scripts/sign-release.sh: signs, verifies, refuses a 0644
# key, and leaves no key material behind. Throwaway keys live in a mktemp dir.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
package="$repo_root/apps/auxesis-mac"
work="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-sign-release.XXXXXX")"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-signer-build.XXXXXX")"
# The signer's own lock, not the CI build lock: the signer builds into a
# scratch dir of its own and never touches the shared Swift build, so it must
# not wait for a lock a CI job holds for the whole job (that job would then
# wait for this script in turn). The wait is bounded, so a stuck lock cannot
# hang the gate.
lock=/tmp/auxesis-sign.lock
locked=0
waited=0

fail=0
note() { printf '%s\n' "$*"; }
fail_case() { note "FAIL: $*"; fail=1; }
expect_fail() {
    if "$@" >/dev/null 2>&1; then fail_case "expected a non-zero exit: $*"; fi
}

cleanup() {
    if [[ "$locked" == 1 ]]; then rmdir "$lock" 2>/dev/null || true; fi
    rm -rf "$work" "$scratch"
}
trap cleanup EXIT

# Serialize with another signer self-test.
until mkdir "$lock" 2>/dev/null; do
    if (( waited >= 300 )); then
        note "FAIL: $lock is held by another signer test; giving up"
        exit 1
    fi
    sleep 5
    waited=$(( waited + 5 ))
done
locked=1

note "build ReleaseSigner"
bin_dir="$(swift build --disable-sandbox --package-path "$package" --scratch-path "$scratch" \
    --cache-path "$scratch/swiftpm-cache" --config-path "$scratch/swiftpm-config" \
    --security-path "$scratch/swiftpm-security" -c debug --product ReleaseSigner --show-bin-path)"
swift build --disable-sandbox --package-path "$package" --scratch-path "$scratch" \
    --cache-path "$scratch/swiftpm-cache" --config-path "$scratch/swiftpm-config" \
    --security-path "$scratch/swiftpm-security" -c debug --product ReleaseSigner >/dev/null
export AUXESIS_RELEASE_SIGNER_BIN="$bin_dir/ReleaseSigner"
[[ -x "$AUXESIS_RELEASE_SIGNER_BIN" ]] || { note "FAIL: signer not built"; exit 1; }

sign="$repo_root/scripts/sign-release.sh"
manifest="$work/release.json"
printf '%s\n' '{"version":"1.2.3","build":42,"minOS":"14.0","dmgURL":"https://updates.test/a.dmg","dmgSHA256":"0000000000000000000000000000000000000000000000000000000000000000","dmgSize":12345,"minAllowedBuild":40}' > "$manifest"

# The release bundle: its CFBundleVersion is the build number the manifest
# must carry.
bundle="$work/Auxesis.app"
mkdir -p "$bundle/Contents"
plutil -create xml1 "$bundle/Contents/Info.plist"
plutil -insert CFBundleVersion -integer 42 "$bundle/Contents/Info.plist"
export AUXESIS_RELEASE_APP_BUNDLE="$bundle"

# 1. generate: private key 0600, public key beside it.
"$sign" generate "$work/release.key" >/dev/null
[[ -f "$work/release.key" ]] || fail_case "generate wrote no private key"
[[ -f "$work/release.key.pub" ]] || fail_case "generate wrote no public key"
mode="$(stat -f '%Lp' "$work/release.key")"
[[ "$mode" == "600" ]] || fail_case "private key mode is $mode, expected 600"

# 2. sign then verify.
"$sign" sign "$work/release.key" "$manifest" >/dev/null
[[ -f "$manifest.sig" ]] || fail_case "sign wrote no .sig"
"$sign" verify "$work/release.key.pub" "$manifest" "$manifest.sig" >/dev/null || fail_case "verify rejected a valid signature"

# 2b. a manifest without a positive dmgSize is refused before signing.
printf '%s\n' '{"version":"1.2.3","build":42}' > "$work/no-size.json"
expect_fail "$sign" sign "$work/release.key" "$work/no-size.json" "$work/no-size.sig"
[[ ! -f "$work/no-size.sig" ]] || fail_case "sign wrote a .sig for a manifest without dmgSize"

# 2c. a manifest whose build is not the bundle's build number is refused.
printf '%s\n' '{"version":"1.2.3","build":41,"minOS":"14.0","dmgURL":"https://updates.test/a.dmg","dmgSHA256":"0000000000000000000000000000000000000000000000000000000000000000","dmgSize":12345,"minAllowedBuild":40}' > "$work/wrong-build.json"
expect_fail "$sign" sign "$work/release.key" "$work/wrong-build.json" "$work/wrong-build.sig"
[[ ! -f "$work/wrong-build.sig" ]] || fail_case "sign wrote a .sig for a manifest with the wrong build"

# 3. a tampered manifest fails verification.
cp "$manifest" "$work/tampered.json"
printf ' ' >> "$work/tampered.json"
expect_fail "$sign" verify "$work/release.key.pub" "$work/tampered.json" "$manifest.sig"

# 4. signing refuses a group/other-readable key (0644).
chmod 0644 "$work/release.key"
if "$sign" sign "$work/release.key" "$manifest" "$work/refused.sig" >/dev/null 2>"$work/refuse.err"; then
    fail_case "sign accepted a 0644 private key"
fi
grep -q "refusing" "$work/refuse.err" || fail_case "refusal message did not explain the mode"

# 5. no key material is left in the repo.
if find "$repo_root" \
    \( -path "$repo_root/.git" -o -path "$repo_root/.build" \) -prune -o \
    \( -name 'release.key' -o -name 'release.key.pub' \) -print | grep -q .; then
    fail_case "a key file was left in the repo"
fi

# 6. the throwaway directory is gone after cleanup.
rm -rf "$work"
[[ ! -e "$work" ]] || fail_case "temp key dir was not deleted"

if [[ "$fail" != 0 ]]; then
    note "test-sign-release: FAILED"
    exit 1
fi
note "test-sign-release: OK"
