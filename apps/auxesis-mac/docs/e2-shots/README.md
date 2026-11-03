# E2 screenshots

`NN-name-side.png`: the prototype on the left, the SwiftUI app on the right, both at
1440×900. The prototype shots are not part of this repository: point
`AUXESIS_MAC_PROTO_SHOTS` at your own copy of them to get the side-by-side
files. The SwiftUI side is rendered offscreen from fixture data (Camille
Exemple, Exemple SARL): no screen capture.

    cd apps/auxesis-mac && T=$(mktemp -d) && swift build --scratch-path "$T"
    S=$(mktemp -d)
    env -i HOME="$S" AUXESIS_HOME="$S/.auxesis" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 \
      AUXESIS_MAC_FIXTURE=team AUXESIS_MAC_SNAPSHOT="$S/shots" \
      "$T/debug/AuxesisMac"
    rm -rf "$T" "$S"   # after copying what you need

Fixtures and snapshots only work with `AUXESIS_SANDBOX=1`.

| Shot | Prototype |
|---|---|
| 01 chief thread, team at work | 32 |
| 02 delegation rows expanded | 33 |
| 03 Mail thread opened from a delegation ("‹ Aux") | 34 |
| 04 approval sent, 10-second Undo | 05 |
| 05 approval edited in place | 04 |
| 06 Waiting for you | 36 |
| 07 agent profile (⌘I) | 37 |
| 08 "What Aux sent to its brain" swap | 40 |
| 09 Stop all | 39 |
| 10 Ledger with skill hash rows | 25 (pre-team Ledger) |
| 11 Settings, Providers | 26 (Settings sheet) |
| 14 menu bar | 15 |
| 16 empty chief | 21 |
| 17, 18 dark | 41, 29 |

No prototype exists for `12-settings-coverage.png` (all 53 `PathId::ALL` rows), `13-settings-budgets.png`
or `15-clients-empty.png` (the E1 empty state).

`hero-*.png`: the hero path against a real sandboxed auxd (main, fake provider). 1: start; 2: the
test provider added from Settings; 3: a message sent and the reply; 4: Coverage from
`GET /v1/privacy/coverage`; 5: the Ledger read from `GET /v1/activity`.
