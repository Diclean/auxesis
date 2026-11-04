# Install Auxesis on your Mac (from source)

Français : [INSTALL.fr.md](INSTALL.fr.md)

This guide is for a person who cloned this repository and wants to run Auxesis on their own
Mac. There is no installer to download, and no release has been published yet. You build the app
and the daemon yourself, then you install the disk image. The [`README`](../README.md) says what
Auxesis is, and [`CONTRIBUTING`](../CONTRIBUTING.md) lists the gates to run before a push.

## 1. What you need

| Tool | Version | Why |
| --- | --- | --- |
| macOS | 14 (Sonoma) or later, on Apple Silicon | the app and the daemon |
| Rust | 1.99.0, pinned in `rust-toolchain.toml` | the daemon, the CLI, the privacy kernel |
| Swift | 5.9 or later (`swift-tools-version: 5.9` in `apps/auxesis-mac/Package.swift`) | the app |
| Xcode Command Line Tools | with Swift 6.2 or later | `swift build`; the full Xcode app is not needed |

Linux and Windows are not supported.

1. Install Rust with [rustup](https://rustup.rs). It reads `rust-toolchain.toml` and installs
   the pinned toolchain by itself.
2. Install the Command Line Tools with `xcode-select --install`.

## 2. Clone the repository

```sh
git clone https://github.com/Diclean/auxesis.git
cd auxesis
```

Check the lockfile. This command prints nothing when the lockfile is fine:

```sh
cargo metadata --locked --format-version 1 >/dev/null
```

## 3. Build the daemon and the CLI

The Rust workspace holds the daemon (`auxd`), the CLI (`aux`) and the privacy kernel. The
kernel crates come from the public `auxesis-privacy-kernel` repository, a git dependency pinned
to tag `v0.1.1`; Cargo fetches that one repository when it builds.

```sh
cargo build --workspace --locked
```

The first build takes a few minutes. Later builds are fast. The binaries land in `target/debug/`.

## 4. Build the app

The app is a separate Swift package, under `apps/auxesis-mac/`.

```sh
apps/auxesis-mac/scripts/make-app.sh
```

The result is `apps/auxesis-mac/build/Auxesis.app`. The script signs the bundle ad-hoc, so no
developer identity is needed and the Keychain is never touched. macOS asks you to confirm the
first time you open it; section 6 says how.

## 5. The disk image

`scripts/package-mac.sh` builds the same app and writes a disk image you can install from:

```sh
scripts/package-mac.sh
```

It writes in `dist/`:

- `Auxesis.app` — the signed bundle, next to the image
- `Auxesis-<version>.dmg` — a read-only disk image holding `Auxesis.app` and a shortcut to your
  `Applications` folder
- `Auxesis-<version>.dmg.sha256` — the checksum of the image

It also builds into `target/` and `apps/auxesis-mac/.build/`, and stages the bundle in a
temporary directory it deletes on exit.

The image holds the app, the daemon it supervises (`Auxesis.app/Contents/Resources/bin/auxd`),
the licence notices and the icon. The bundle inside is signed ad-hoc: no Apple identity, no
Keychain, no prompt. This is a local build from your own source, not a published release.

## 6. Install it

1. Double-click `Auxesis-<version>.dmg`. The Finder opens a window with `Auxesis.app` and the
   `Applications` shortcut.
2. Drag `Auxesis.app` onto `Applications`. The copy in the image is read-only; the copy in
   Applications is the one that runs.
3. The first launch may need one confirmation. The build is not signed by Apple, so macOS may ask
   you to confirm before the app opens. Right-click (or Control-click) `Auxesis.app` in
   Applications, choose **Open**, then **Open Anyway**. Or open System Settings, Privacy and
   Security, scroll down to the message about Auxesis, click **Open Anyway**, then click
   **Open**.
4. Eject the image: select it in the Finder and press Cmd-E. The `.dmg` file can be deleted
   afterwards.
5. The app shows a setup screen on the first launch. It asks for nothing until you press a
   button. Section 10 lists the permissions.

The app is in English and French. It follows the first language in System Settings, General,
Language and Region; any other language gets English. Settings, General shows the one in use.

## 7. First run

1. Try it in a throwaway home first. Nothing of yours is read, and the temporary folder is
   deleted when you stop:

   ```sh
   scripts/run-dev.sh --sandbox
   ```

2. Quit the app with Cmd-Q to stop everything.

3. When the sandbox run looks right, run it against your real home: `scripts/run-dev.sh`.

4. Check the installation at any time with `cargo run -p aux-cli -- doctor`.

5. To keep the daemon running between reboots, install it as a launchd agent with
   `cargo run -p aux-cli -- install`.

## 8. Where the data lives

- `~/.auxesis/` holds everything the daemon owns: `config.toml`, `store.db` (an encrypted
  SQLite store), `logs/`, `providers.toml` and the files you write yourself. Set
  `AUXESIS_HOME` to use another directory.
- `~/Library/LaunchAgents/dev.auxesis.auxd.plist` is the login agent, if you installed one.
- `/Applications/Auxesis.app` is the app you installed from the image, or
  `~/Applications/Auxesis.app` if you put it there.
- `apps/auxesis-mac/build/Auxesis.app` is the app you built.

The [`README`](../README.md) has a short list, under "Where files live"; this guide has the
details.

## 9. Add your model key

Auxesis ships no model. You point it at a provider you already pay for, with your own key.

1. Write the provider entry. Create `~/.auxesis/providers.toml`:

   ```toml
   [[provider]]
   id       = "my-provider"                       # your own id, [a-z0-9-]
   kind     = "openai"                            # openai | anthropic | ollama | acp
   base_url = "https://api.example.com/v1"        # https, or http on loopback only
   key      = "env:AUX_KEY_MY_PROVIDER"
   models   = ["my-model"]

   [brain]
   default = "my-provider/my-model"               # <provider>/<model>
   ```

2. Store the key. The key is read from standard input, so it never appears in your shell
   history and never appears in the process list:

   ```sh
   cargo run -p aux-cli -- secret set my-provider   # paste the key, then press Return
   ```

   This writes `AUX_KEY_MY_PROVIDER` into `~/.auxesis/.env`, with mode `0600`. The value is
   never passed on the command line.

3. Check it with `cargo run -p aux-cli -- secret check my-provider`. It says whether a key
   exists, and never prints it.

You can also add a provider in the app, under Settings, in the Providers panel. The key goes to
the same `~/.auxesis/.env` file.

Never paste a real key into a chat, into a document, or into a commit. In this guide the
placeholder is `sk-...`.

The [`providers` contract](providers.md) describes every field of `providers.toml`.

## 10. The permissions macOS asks for

The app shows a setup screen on first launch. It lists four permissions, says why each one is
needed, and asks for nothing until you press a button. You can skip the screen and come back
later, from Settings, under General.

1. **Calendar and Reminders.** Reads your events and reminders for the morning brief, and to
   plan meetings.
2. **Notifications.** One banner when something waits for your yes. Nothing while Auxesis is
   stopped.
3. **Messages.** Lets Auxesis text you through Messages, for example to ask for your yes.
4. **Full Disk Access.** Only if you use Messages. It lets the daemon read your replies in
   Messages. macOS never lets an app ask for this one: open System Settings, Privacy and
   Security, Full Disk Access, press `+`, and add the `auxd` file, not the whole app. The setup
   screen shows you which file to add.

## 11. Uninstall

1. Quit the app with Cmd-Q.
2. Remove the login agent, if you installed one. This removes
   `~/Library/LaunchAgents/dev.auxesis.auxd.plist`:

   ```sh
   cargo run -p aux-cli -- uninstall
   ```

3. Delete the app. Move `Auxesis.app` from Applications to the Trash. If you built it from
   source, delete the bundle and the disk image too:

   ```sh
   rm -rf apps/auxesis-mac/build/Auxesis.app
   rm -rf dist
   ```

4. Delete your data. This cannot be undone. It removes your settings, your conversations, your
   logs, and the `.env` file that holds your key:

   ```sh
   rm -rf ~/.auxesis
   ```

5. If you used the macOS Keychain, delete the item there too. The Keychain is off by default:
   nothing writes to it unless you set `AUXESIS_ALLOW_KEYCHAIN=1` yourself.

## 12. How to update

From the app: **Check for Updates…** in the Auxesis menu. The app fetches one feed over https,
checks the signature of the manifest, then the size and the checksum of the image, downloads the
image to a temporary folder and shows it in the Finder. It never installs anything and never runs
what it downloads: open the image and drag the new `Auxesis.app` onto the old one in Applications
to replace it.

The daily check is off by default. When you turn it on, the app keeps only a boolean and a
timestamp.

An update is offered only when the manifest carries a build number higher than the app's own.
The packaged app carries an integer build number (`--build`, else the commit count); an app
built from the sources with `apps/auxesis-mac/scripts/make-app.sh` carries 1.

Until a release is published, the check reports a failure and nothing is downloaded. The alert
reads "Update check failed". With the placeholder release key that is still in the app, the
signature never matches and the message is "The update manifest could not be trusted, so nothing
was downloaded." With no feed published at all, the request fails first, and the alert then
carries the error the request returned, for example "The update server answered with status
404."

Until then, update from the source: `git pull`, build again (sections 3 and 4), and install the
new app over the old one.

[`releasing.md`](releasing.md) has the details of a release: the manifest, the signature and the
feed.
