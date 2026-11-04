# Installer Auxesis sur votre Mac (depuis les sources)

English : [INSTALL.md](INSTALL.md)

Ce guide est pour une personne qui a cloné ce dépôt et veut faire tourner Auxesis sur son
propre Mac. Il n'y a pas d'installateur à télécharger, et aucune version n'a encore été publiée.
Vous compilez l'app et le démon vous-même, puis vous installez l'image disque. Le
[`README`](../README.md) explique ce qu'est Auxesis, et [`CONTRIBUTING`](../CONTRIBUTING.md) liste
les portes à passer avant un push.

## 1. Ce qu'il vous faut

| Outil | Version | Pourquoi |
| --- | --- | --- |
| macOS | 14 (Sonoma) ou plus récent, sur Apple Silicon | l'app et le démon |
| Rust | 1.99.0, épinglé dans `rust-toolchain.toml` | le démon, la CLI, le noyau de confidentialité |
| Swift | 5.9 ou plus récent (`swift-tools-version: 5.9` dans `apps/auxesis-mac/Package.swift`) | l'app |
| Xcode Command Line Tools | une version récente suffit | `swift build` ; l'app Xcode complète n'est pas nécessaire |

Linux et Windows ne sont pas pris en charge.

1. Installez Rust avec [rustup](https://rustup.rs). Il lit `rust-toolchain.toml` et installe
   lui-même la version épinglée.
2. Installez les Command Line Tools avec `xcode-select --install`.

## 2. Cloner le dépôt

```sh
git clone https://github.com/Diclean/auxesis.git
cd auxesis
```

Vérifiez le fichier de verrouillage. Cette commande n'affiche rien quand tout va bien :

```sh
cargo metadata --locked --format-version 1 >/dev/null
```

## 3. Compiler le démon et la CLI

L'espace de travail Rust contient le démon (`auxd`), la CLI (`aux`) et le noyau de
confidentialité. Les crates du noyau viennent du dépôt public `auxesis-privacy-kernel`, une
dépendance git épinglée au tag `v0.1.3` ; Cargo récupère ce seul dépôt au moment de compiler.

```sh
cargo build --workspace --locked
```

La première compilation prend quelques minutes. Les suivantes sont rapides. Les binaires
arrivent dans `target/debug/`.

## 4. Compiler l'app

L'app est un paquet Swift séparé, sous `apps/auxesis-mac/`.

```sh
apps/auxesis-mac/scripts/make-app.sh
```

Le résultat est `apps/auxesis-mac/build/Auxesis.app`. Le script signe le bundle à la volée :
aucune identité de développeur n'est nécessaire et le trousseau n'est jamais touché. macOS vous
demande de confirmer la première fois que vous l'ouvrez ; la section 6 explique comment.

## 5. L'image disque

`scripts/package-mac.sh` construit la même app et écrit une image disque que vous pouvez
installer :

```sh
scripts/package-mac.sh
```

Il écrit dans `dist/` :

- `Auxesis.app` — le bundle signé, à côté de l'image
- `Auxesis-<version>.dmg` — une image disque en lecture seule, contenant `Auxesis.app` et un
  raccourci vers votre dossier `Applications`
- `Auxesis-<version>.dmg.sha256` — la somme de contrôle de l'image

Il compile aussi dans `target/` et `apps/auxesis-mac/.build/`, et prépare le bundle dans un
dossier temporaire qu'il supprime en sortant.

L'image contient l'app, le démon qu'elle supervise
(`Auxesis.app/Contents/Resources/bin/auxd`), les avis de licence et l'icône. Le bundle qu'elle
contient est signé à la volée : aucune identité Apple, aucun trousseau, aucune demande. C'est
une compilation locale, à partir de votre propre source, pas une version publiée.

## 6. L'installer

1. Faites un double-clic sur `Auxesis-<version>.dmg`. Le Finder ouvre une fenêtre avec
   `Auxesis.app` et le raccourci `Applications`.
2. Glissez `Auxesis.app` sur `Applications`. La copie dans l'image est en lecture seule ; celle
   dans Applications est celle qui se lance.
3. Le premier lancement peut demander une confirmation : le build n'est pas signé par Apple,
   donc macOS peut vous demander de confirmer avant d'ouvrir l'app. Faites un clic droit (ou
   Ctrl-clic) sur `Auxesis.app` dans Applications, choisissez **Ouvrir**, puis **Ouvrir quand
   même**. Ou ouvrez Réglages Système, Confidentialité et sécurité, descendez jusqu'au message
   sur Auxesis, cliquez sur **Ouvrir quand même**, puis cliquez sur **Ouvrir**.
4. Éjectez l'image : sélectionnez-la dans le Finder et appuyez sur Cmd-E. Le fichier `.dmg` peut
   être supprimé ensuite.
5. L'app affiche un écran de réglage au premier lancement. Elle ne demande rien avant que vous
   appuyiez sur un bouton. La section 10 liste les permissions.

L'app est en anglais et en français. Elle suit la première langue de Réglages Système, Général,
Langue et région ; une autre langue donne l'anglais. Réglages, Général indique celle qui est
utilisée.

## 7. Premier lancement

1. Essayez d'abord dans un dossier temporaire. Rien de ce qui vous appartient n'est lu, et le
   dossier temporaire est supprimé quand vous arrêtez :

   ```sh
   scripts/run-dev.sh --sandbox
   ```

2. Quittez l'app avec Cmd-Q pour tout arrêter.

3. Quand l'essai en bac à sable vous convient, lancez-la sur votre vrai dossier personnel :
   `scripts/run-dev.sh`.

4. Vérifiez l'installation à tout moment avec `cargo run -p aux-cli -- doctor`.

5. Pour garder le démon actif entre deux redémarrages, installez-le comme agent launchd avec
   `cargo run -p aux-cli -- install`.

## 8. Où sont les données

- `~/.auxesis/` contient tout ce que le démon possède : `config.toml`, `store.db` (une base
  SQLite chiffrée), `logs/`, `providers.toml` et les fichiers que vous écrivez vous-même. Mettez
  `AUXESIS_HOME` pour utiliser un autre dossier.
- `~/Library/LaunchAgents/dev.auxesis.auxd.plist` est l'agent de démarrage, si vous en avez
  installé un.
- `/Applications/Auxesis.app` est l'app installée depuis l'image, ou `~/Applications/Auxesis.app`
  si vous l'avez mise là.
- `apps/auxesis-mac/build/Auxesis.app` est l'app que vous avez compilée.

Le [`README`](../README.md) a une liste courte, à la section « Where files live » ; ce guide
donne les détails.

## 9. Ajouter votre clé de modèle

Auxesis ne contient aucun modèle. Vous le pointez vers un fournisseur que vous payez déjà,
avec votre propre clé.

1. Écrivez l'entrée du fournisseur. Créez `~/.auxesis/providers.toml` :

   ```toml
   [[provider]]
   id       = "my-provider"                       # votre id, [a-z0-9-]
   kind     = "openai"                            # openai | anthropic | ollama | acp
   base_url = "https://api.example.com/v1"        # https, ou http sur la boucle locale seulement
   key      = "env:AUX_KEY_MY_PROVIDER"
   models   = ["my-model"]

   [brain]
   default = "my-provider/my-model"               # <provider>/<model>
   ```

2. Enregistrez la clé. La clé est lue sur l'entrée standard : elle n'apparaît jamais dans
   votre historique de shell et jamais dans la liste des processus :

   ```sh
   cargo run -p aux-cli -- secret set my-provider   # collez la clé, puis appuyez sur Entrée
   ```

   Cela écrit `AUX_KEY_MY_PROVIDER` dans `~/.auxesis/.env`, avec le mode `0600`. La valeur
   n'est jamais passée sur la ligne de commande.

3. Vérifiez avec `cargo run -p aux-cli -- secret check my-provider`. La commande dit si une clé
   existe, et ne l'affiche jamais.

Vous pouvez aussi ajouter un fournisseur dans l'app, dans Réglages, dans le panneau
Fournisseurs. La clé va dans le même fichier `~/.auxesis/.env`.

Ne collez jamais une vraie clé dans une discussion, dans un document ou dans un commit. Dans
ce guide, le placeholder est `sk-...`.

Le [contrat des fournisseurs](providers.md) décrit chaque champ de `providers.toml`.

## 10. Les permissions que macOS demande

L'app affiche un écran de réglage au premier lancement. Il liste quatre permissions, dit
pourquoi chacune est utile, et ne demande rien avant que vous appuyiez sur un bouton. Vous
pouvez passer et revenir plus tard, depuis Réglages, dans Général.

1. **Calendrier et Rappels.** Lit vos événements et rappels pour le brief du matin, et pour
   planifier des rendez-vous.
2. **Notifications.** Une bannière quand quelque chose attend votre oui. Rien quand Auxesis
   est arrêté.
3. **Messages.** Permet à Auxesis de vous écrire via Messages, par exemple pour demander votre
   oui.
4. **Accès complet au disque.** Seulement si vous utilisez Messages. C'est ce qui permet au
   démon de lire vos réponses dans Messages. macOS ne laisse jamais une app demander celle-là :
   ouvrez Réglages Système, Confidentialité et sécurité, Accès complet au disque, appuyez sur
   `+`, et ajoutez le fichier `auxd`, pas toute l'app. L'écran de réglage vous montre quel
   fichier ajouter.

## 11. Désinstaller

1. Quittez l'app avec Cmd-Q.
2. Retirez l'agent de démarrage, si vous en avez installé un. Ceci supprime
   `~/Library/LaunchAgents/dev.auxesis.auxd.plist` :

   ```sh
   cargo run -p aux-cli -- uninstall
   ```

3. Supprimez l'app. Glissez `Auxesis.app` d'Applications vers la Corbeille. Si vous l'avez
   compilée depuis les sources, supprimez aussi le bundle et l'image disque :

   ```sh
   rm -rf apps/auxesis-mac/build/Auxesis.app
   rm -rf dist
   ```

4. Supprimez vos données. C'est irréversible. Vos réglages, vos conversations, vos journaux
   et le fichier `.env` qui contient votre clé partent avec :

   ```sh
   rm -rf ~/.auxesis
   ```

5. Si vous avez utilisé le trousseau macOS, supprimez l'élément là-bas aussi. Le trousseau
   est fermé par défaut : rien n'y écrit sauf si vous mettez vous-même
   `AUXESIS_ALLOW_KEYCHAIN=1`.

## 12. Comment mettre à jour

Depuis l'app : **Rechercher les mises à jour…** dans le menu Auxesis. L'app récupère un seul flux
en https, vérifie la signature du manifeste, puis la taille et la somme de contrôle de l'image,
télécharge l'image dans un dossier temporaire et l'affiche dans le Finder. Elle n'installe rien
et n'exécute jamais ce qu'elle télécharge : ouvrez l'image et glissez le nouveau `Auxesis.app`
sur l'ancien, dans Applications, pour le remplacer.

La vérification quotidienne est désactivée par défaut. Quand vous l'activez, l'app ne garde qu'un
booléen et un horodatage.

Une mise à jour n'est proposée que si le manifeste porte un numéro de build supérieur à celui de
l'app. L'app empaquetée porte un numéro de build entier (`--build`, sinon le nombre de commits) ;
une app compilée depuis les sources avec `apps/auxesis-mac/scripts/make-app.sh` porte 1.

Aucune version n'a encore été publiée : la vérification signale un échec et ne télécharge rien.
L'alerte affiche « Update check failed ». Avec la clé de publication de remplacement qui est
encore dans l'app, la signature ne correspond jamais et le message est « The update manifest
could not be trusted, so nothing was downloaded. ». Sans flux publié du tout, la requête échoue
d'abord, et l'alerte porte alors l'erreur renvoyée, par exemple « The update server answered
with status 404. ».

D'ici là, mettez à jour depuis les sources : `git pull`, compilez à nouveau (sections 3 et 4), et
installez la nouvelle app par-dessus l'ancienne.

[`releasing.md`](releasing.md) donne le détail d'une version : le manifeste, la signature et le
flux.
