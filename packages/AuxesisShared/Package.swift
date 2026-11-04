// swift-tools-version: 5.9
// AuxesisShared — the one copy of the models, the theme and the pure text
// helpers, shared by the Mac app (apps/auxesis-mac) and the coming iPhone app.
//
// This package may import Foundation, CoreGraphics and CryptoKit only. The
// rule is pinned by `scripts/check-shared-imports.sh`, which the Swift gate
// runs, so a shared file can never reach for AppKit, EventKit, Vision or
// Darwin and quietly become Mac-only.
//
// The tests stay in the Mac package (AuxesisKitTests): that package carries
// the in-repo XCTest/Testing shims the Command Line Tools toolchain needs, and
// the shared code has no behaviour of its own to test twice.
import PackageDescription

let package = Package(
    name: "AuxesisShared",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "AuxesisShared", targets: ["AuxesisShared"]),
    ],
    targets: [
        .target(name: "AuxesisShared"),
    ]
)
