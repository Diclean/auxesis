// swift-tools-version: 5.9
// Auxesis Mac — the SwiftUI front for the auxd local API (see README.md).
//
// Command Line Tools only: no Xcode, no XCTest framework. The two targets
// `XCTest` and `Testing` below are a tiny in-repo test runner that plugs into
// SwiftPM's generated test runner (`swift test` works with CLT). With a full
// Xcode toolchain those two targets would shadow the real frameworks; delete
// them and the test target's dependency on `Testing` in that case.
import PackageDescription

let package = Package(
    name: "AuxesisMac",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AuxesisKit", targets: ["AuxesisKit"]),
        .executable(name: "AuxesisMac", targets: ["AuxesisMac"]),
    ],
    dependencies: [
        // The one copy of the models, the theme and the pure text helpers.
        // The phone app will link the same package; the Mac app keeps only
        // what is Mac-only (AppKit, EventKit, Vision, the bridge, the updater).
        .package(path: "../../packages/AuxesisShared"),
    ],
    targets: [
        // Offline release-manifest signer: a dev tool, never bundled in
        // the app. `scripts/sign-release.sh` drives it.
        .executableTarget(name: "ReleaseSigner"),
        // CLT-only test runner (see header). Not a product.
        .target(name: "XCTest"),
        .target(name: "Testing", dependencies: ["XCTest"]),
        // Everything that can be tested headlessly: models, client, store, copy, palette.
        .target(name: "AuxesisKit", dependencies: ["AuxesisShared"]),
        // The SwiftUI app shell uses system SF Pro fonts.
        .executableTarget(name: "AuxesisMac", dependencies: ["AuxesisKit"], exclude: ["Resources"]),
        .testTarget(
            name: "AuxesisKitTests",
            dependencies: ["AuxesisKit", "AuxesisMac", "Testing"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
