#!/usr/bin/env bash
# Sign an Auxesis release manifest with the pinned Ed25519 release key.
#
#   scripts/sign-release.sh generate <key-path>
#   scripts/sign-release.sh sign <key-path> <manifest.json> [<out.sig>]
#   scripts/sign-release.sh verify <public-key-path> <manifest.json> <sig>
#
# The private key never lives in the repo and is never taken from the
# environment: it is read from <key-path>, which must be mode 0600.
#
# How a release is signed, in order:
#
#   1. Build the bundle and the image:
#        scripts/package-mac.sh --version <version>
#      It writes dist/Auxesis-<version>.dmg and the matching .sha256.
#   2. Write the release manifest: a JSON document with version, build,
#      minOS, dmgURL, dmgSHA256, dmgSize and minAllowedBuild. dmgSize is
#      the exact size of the .dmg in bytes. `build` is the build number of
#      the packaged app (`CFBundleVersion`).
#   3. Sign the manifest with the release key:
#        scripts/sign-release.sh sign <key-path> <manifest.json>
#      It writes <manifest.json>.sig next to it.
#   4. Check the signature before publishing anything:
#        scripts/sign-release.sh verify <key-path>.pub <manifest.json> \
#            <manifest.json>.sig
#   5. Publish the .dmg, its .sha256, the manifest and the manifest.sig
#      side by side. The app fetches the manifest and its .sig, checks the
#      signature against the public key it carries, then the size and the
#      hash of the downloaded image.
#
# Every signed manifest must carry a positive integer `dmgSize` (the exact dmg
# size in bytes) and a positive integer `build` equal to the build number of
# the release bundle (dist/Auxesis.app, or $AUXESIS_RELEASE_APP_BUNDLE), so a
# release cannot be signed that the updater would later reject, or that the
# shipped app would never compare itself with.
#
# The signer itself is a SwiftPM executable target (`ReleaseSigner`) that is
# not shipped in Auxesis.app. Set AUXESIS_RELEASE_SIGNER_BIN to use a
# prebuilt binary (the shell test does), otherwise it is built with `swift run`.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
package="$here/../apps/auxesis-mac"
repo_root="$(cd "$here/.." && pwd)"

command="${1:-}"
if [[ "$command" == "sign" || "$command" == "--sign" ]]; then
    manifest="${3:-}"
    if [[ -n "$manifest" && -f "$manifest" ]]; then
        dmg_size="$(plutil -extract dmgSize raw -o - -- "$manifest" 2>/dev/null || true)"
        if ! [[ "$dmg_size" =~ ^[0-9]+$ ]] || [[ "$dmg_size" -le 0 ]]; then
            echo "sign-release: refusing $manifest: dmgSize must be a positive integer" >&2
            exit 2
        fi
        # The build number of the manifest must be the build number of the
        # bundle that is released: the app compares the two.
        build="$(plutil -extract build raw -o - -- "$manifest" 2>/dev/null || true)"
        [[ "$build" =~ ^[0-9]+$ && "$build" -gt 0 ]] \
            || { echo "sign-release: refusing $manifest: build must be a positive integer" >&2; exit 2; }
        bundle="${AUXESIS_RELEASE_APP_BUNDLE:-$repo_root/dist/Auxesis.app}"
        plist="$bundle/Contents/Info.plist"
        [[ -f "$plist" ]] \
            || { echo "sign-release: refusing $manifest: no release bundle at $bundle (set AUXESIS_RELEASE_APP_BUNDLE)" >&2; exit 2; }
        bundle_build="$(plutil -extract CFBundleVersion raw -o - -- "$plist" 2>/dev/null || true)"
        [[ "$bundle_build" == "$build" ]] \
            || { echo "sign-release: refusing $manifest: build $build is not the bundle's build ($bundle_build)" >&2; exit 2; }
    fi
fi

if [[ -n "${AUXESIS_RELEASE_SIGNER_BIN:-}" ]]; then
    exec "$AUXESIS_RELEASE_SIGNER_BIN" "$@"
fi

scratch="${AUXESIS_RELEASE_SIGNER_SCRATCH:-$package/.build}"
exec swift run \
    --disable-sandbox \
    --package-path "$package" \
    --scratch-path "$scratch" \
    --cache-path "$scratch/swiftpm-cache" \
    --config-path "$scratch/swiftpm-config" \
    --security-path "$scratch/swiftpm-security" \
    -c debug ReleaseSigner "$@"
