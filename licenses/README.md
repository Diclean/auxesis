# Third-party licence texts

One file per SPDX licence id: `licenses/<SPDX-id>.txt`. Every text here is the
official SPDX text, **verbatim**, taken from the SPDX licence-list-data
repository (<https://github.com/spdx/license-list-data>, the `text/<id>.txt`
file of each id). Nothing is edited: a text that differs from the official one
is not the licence it claims to be, so these files are copied as they are.

What is in here:

* the licence of every component `NOTICE` names — Apache-2.0, MIT,
  BSD-3-Clause, BSD-2-Clause, OFL-1.1;
* the licence of every crate of the locked dependency graph, and every
  exception one of them uses (LLVM-exception). The ids come from the licence
  expressions of `THIRD-PARTY-LICENSES.txt`.

The licence of Auxesis itself is **not** here: it is the PolyForm
Noncommercial 1.0.0 text of `LICENSE` at the repository root, and the app
bundle carries it there next to this folder.

`scripts/third-party-licenses.py` reads the licence expressions of the locked
graph and refuses to write the list when one of the ids it found has no text
here. A dependency that arrives with a new licence therefore cannot ship
before its text is added.

These files travel with the app: `scripts/package-mac.sh` copies this folder
into `Auxesis.app/Contents/Resources/licenses`, next to `NOTICE` and
`THIRD-PARTY-LICENSES.txt`.

To add the text of a new licence, fetch it from the SPDX licence-list-data
repository and commit it unedited:

    gh api -H "Accept: application/vnd.github.raw" \
        "repos/spdx/license-list-data/contents/text/<SPDX-id>.txt" \
        > "licenses/<SPDX-id>.txt"
