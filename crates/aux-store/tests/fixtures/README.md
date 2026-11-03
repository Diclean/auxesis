# aux-store fixtures

`store-v10-rusqlite031.sqlite` is a real schema-v10 store written by the
**pre-DEPS-1** dependency stack: `rusqlite 0.31.0` → `libsqlite3-sys 0.28.0`
with bundled **SQLite 3.45.0** (`file` reports `last written using SQLite
version 3045000`). It is used by
`old_rusqlite_v10_store_opens_reads_and_writes` in `src/lib.rs` to prove that
`aux-store` still opens, migrates (no-op at v10), reads and writes a store
file created by the old version.

Regenerating the fixture is only meaningful with the old stack. The DDL it was
built from is the v1 → v10 ladder in `crates/aux-store/src/lib.rs` at
`main@d19c78a` (pre-bump), run through a throwaway crate whose only dependency
is `rusqlite = { version = "=0.31.0", features = ["bundled"] }`, followed by
the representative rows the test asserts on. **Never regenerate it with the
new `rusqlite`/SQLite** — that would defeat the point of the test.
