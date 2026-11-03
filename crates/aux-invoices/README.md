# aux-invoices

Pure invoice parsing and totals checks for [Auxesis](https://github.com/Diclean/auxesis), a personal always-on agent app.

- Parses Factur-X/ZUGFeRD CII and UBL e-invoice XML into typed values; size, depth and element counts are bounded and DOCTYPE is refused.
- Checks totals and VAT with deterministic `rust_decimal` arithmetic. `check_totals` returns the issues; a mismatch is reported, never corrected.
- Names bytes by SHA-256 (`sha256_hex`) and detects MIME by signature (`detect_mime`), never by filename.
- No I/O, no network, no store, no file access. Every input is tainted document content.
- Stores nothing: the evidence registry (originals, deduplication, provenance) lives in the Auxesis app.
- Build and test with `cargo test`.

Licensed under Apache-2.0 (see the `LICENSE` in this directory).
