// AuxesisKit re-exports the shared package.
//
// The models, the theme and the pure text helpers now live in
// `packages/AuxesisShared`, so the Mac app and the coming iPhone app share
// one copy. Re-exporting here keeps the app shell and the tests free of
// `import AuxesisShared` lines: they see the shared symbols through
// `import AuxesisKit`, exactly as before the move.
//
// The shared package may import Foundation, CoreGraphics and CryptoKit only;
// `scripts/check-shared-imports.sh` enforces that.
@_exported import AuxesisShared
