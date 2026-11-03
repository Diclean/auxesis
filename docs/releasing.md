# Releasing Auxesis

No release has been published yet: the [`README`](../README.md) says the project is built from
source for now, and no notarised `.dmg` exists. This file describes how a release is made when
there is one, and how the app looks for it. Everything here is what the code does; the script
names are the entry points.

## 1. Build the bundle and the image

    scripts/package-mac.sh --version <version>

It builds `auxd` and the SwiftUI app, assembles `Auxesis.app` (the app binary, the daemon at
`Contents/Resources/bin/auxd`, the licence notices and the icon), signs the bundle ad-hoc, and
writes:

- `<repo>/target/` (or `CARGO_TARGET_DIR`) — the cargo build directory
- `apps/auxesis-mac/.build/` (or `AUXESIS_MAC_SCRATCH`) — the SwiftPM scratch directory
- `$OUT/Auxesis.app` — the signed bundle, next to the image
- `$OUT/Auxesis-<version>.dmg` — a read-only image (UDZO) holding `Auxesis.app` and a shortcut to
  the `Applications` folder, for drag-to-Applications
- `$OUT/Auxesis-<version>.dmg.sha256` — the checksum of the image

`--out` chooses where the last three go; it is `<repo>/dist` by default. The bundle is staged in
a temporary directory that the script deletes on exit. It installs nothing: no LaunchAgent, no
`~/.auxesis`, no Keychain.

The build number the app compares with a release manifest is an integer in `CFBundleVersion`:
`--build N`, else `AUXESIS_BUILD_NUMBER`, else the commit count (`git rev-list --count HEAD`).
The manifest carries the one the bundle has:

    plutil -extract CFBundleVersion raw -o - dist/Auxesis.app/Contents/Info.plist

## 2. Notarisation

There is none today. The bundle is signed ad-hoc (`codesign --force --deep -s -`): no Apple
identity, no keychain, no prompt. macOS therefore does not know the developer, and asks the
owner to confirm the first time the app is opened. A notarised image needs an Apple Developer
identity and `xcrun notarytool`; nothing in this repository does that yet.

## 3. The release manifest

The manifest is a JSON document the app downloads and verifies before it parses it. Its fields are
the ones `ReleaseManifest` declares:

    {
      "version": "0.1.0",
      "build": 2,
      "minOS": "14.0",
      "dmgURL": "https://updates.auxesis.app/Auxesis-0.1.0.dmg",
      "dmgSHA256": "<the sha256 of the .dmg>",
      "dmgSize": 12345678,
      "minAllowedBuild": 1
    }

`dmgSize` is the exact size of the image in bytes. It must be a positive integer: the signer
refuses a manifest without one, so a release cannot be signed that the updater would later reject.

`build` is the number the app compares with its own, and an update is only offered when the
manifest carries a higher one. It is the build number of the packaged app: `package-mac.sh`
writes it into `CFBundleVersion` as an integer (1 or more) and `AppVersion.build` reads it, so
the app reports the build the bundle was made with. The signer refuses a manifest whose `build`
is not the bundle's.

## 4. Sign the manifest

The signature is Ed25519 (CryptoKit `Curve25519.Signing`), detached: it lives in the sibling file
`<manifest>.sig` and covers the exact bytes of the manifest.

    scripts/sign-release.sh generate <key-path>                                # <key-path> (0600) and <key-path>.pub (0644)
    scripts/sign-release.sh sign <key-path> <manifest.json>                    # writes <manifest.json>.sig
    scripts/sign-release.sh verify <key-path>.pub <manifest.json> <manifest.json>.sig

The private key never lives in the repository and is never taken from the environment: it is read
from `<key-path>`, which must be mode `0600`. The signer refuses a key another user on the machine
could read, and refuses to overwrite an existing key file. The public key is the only half that
ships, inside the app (`Updater.pinnedPublicKeyBase64`); the value in the tree today is a
placeholder, to be replaced with the production key before the first signed release.

## 5. Publish the feed

There is no appcast file in this repository. The feed is the manifest and its detached signature,
published side by side with the image and its checksum:

- `https://updates.auxesis.app/release.json` — the manifest
- `https://updates.auxesis.app/release.json.sig` — the detached signature
- `https://updates.auxesis.app/Auxesis-<version>.dmg` — the image the manifest points at

The app reads the first two names; the manifest's `dmgURL` says where the image comes from.

## 6. What the app does with a feed

`apps/auxesis-mac/Sources/AuxesisKit/Updater.swift` holds the whole flow:

1. The manifest is fetched, capped at 64 KiB, and its `.sig` at 1 KiB. A `Content-Length` above
   the cap is refused before the body is read.
2. The signature is checked against the pinned public key **before** the manifest is parsed, so a
   tampered manifest never reaches the decoder.
3. The parsed manifest is checked: its build is newer than the installed one; the update is
   refused when the installed build is below `minAllowedBuild` and the offered one is too; the
   macOS version is at least `minOS`; and `dmgSize` is positive and at most 2 GiB.
4. The image is streamed into a fresh private directory under the system temporary directory. The
   received size must equal the signed `dmgSize`, and its SHA-256 must equal `dmgSHA256`. On any
   failure the file is deleted.
5. The updater never installs anything: it hands the file over and the app reveals it in the
   Finder. Nothing from the image is opened, mounted or executed. The owner opens it and drags
   `Auxesis.app` onto the one in Applications.

Each fetch is one plain `GET` with `User-Agent: Auxesis/<version>`, on an ephemeral session with
cookies disabled: no cookie, no token and no account id are sent. The feed host does see your IP
address, and the User-Agent carries the app version. A redirect is followed only when it stays
on https. The daily check is opt-in and off by default; it stores a boolean and a timestamp in
`UserDefaults`, and nothing else.
