// The build number the updater compares with a release manifest's: an
// integer in CFBundleVersion (scripts/package-mac.sh writes the commit
// count, or the number given with --build).
import Foundation
import Testing
@testable import AuxesisKit

private enum PackagedPlistFixtureError: Error {
    case unavailable
}

@objcMembers @MainActor final class AppVersionTests: XCTestCase {
    func testIntegerBuildIsRead() {
        XCTAssertEqual(AppVersion.build(in: ["CFBundleVersion": 4242]), 4242)
        XCTAssertEqual(AppVersion.build(in: ["CFBundleVersion": "4242"]), 4242)
    }

    func testAnythingElseFallsBackToOne() {
        // The bug this guards: a dotted CFBundleVersion reads as nothing.
        XCTAssertEqual(AppVersion.build(in: ["CFBundleVersion": "0.1.0"]), 1)
        XCTAssertEqual(AppVersion.build(in: nil), 1)
        XCTAssertEqual(AppVersion.build(in: [:]), 1)
    }

    /// The packaged Info.plist: the build number must be an integer, and the
    /// app must read it. scripts/test-package-mac.sh points this at the
    /// bundle it packaged. A plain `swift test` has no such bundle: build a
    /// throwaway one with the real packager, so the check is never skipped.
    func testPackagedInfoPlistCarriesAnIntegerBuild() throws {
        var throwaway: URL?
        defer {
            if let throwaway {
                try? FileManager.default.removeItem(at: throwaway)
            }
        }

        let path: URL
        let expectedBuild: Int?
        if let packaged = ProcessInfo.processInfo.environment["AUXESIS_PACKAGED_INFO_PLIST"] {
            path = URL(fileURLWithPath: packaged)
            expectedBuild = nil
        } else {
            let temp = FileManager.default.temporaryDirectory
                .appendingPathComponent("appversion-\(UUID().uuidString)", isDirectory: true)
            throwaway = temp
            path = try makeThrowawayInfoPlist(at: temp)
            expectedBuild = 4242
        }

        let data = try Data(contentsOf: path)
        let xml = try XCTUnwrapOptional(String(data: data, encoding: .utf8))
        guard let info = try PropertyListSerialization.propertyList(from: data, format: nil)
            as? [String: Any], let number = info["CFBundleVersion"] as? NSNumber
        else {
            return XCTFail("CFBundleVersion is not a number in \(path.path)")
        }
        XCTAssertTrue(xml.contains("<integer>"), "CFBundleVersion must be written as an integer")
        XCTAssertEqual(AppVersion.build(in: info), number.intValue)
        XCTAssertGreaterThanOrEqual(number.intValue, 1, "a packaged build number is 1 or more")
        if let expectedBuild {
            XCTAssertEqual(number.intValue, expectedBuild)
        }
    }

    /// Runs `scripts/package-mac.sh --plist-only` into a mktemp bundle: no
    /// daemon, no app and no signature, but the exact plist a packaged app
    /// ships.
    private func makeThrowawayInfoPlist(at bundle: URL) throws -> URL {
        guard let root = repositoryRoot() else {
            XCTFail("cannot find the repository root from \(#filePath)")
            throw PackagedPlistFixtureError.unavailable
        }
        let script = root.appendingPathComponent("scripts/package-mac.sh")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [
            script.path, "--plist-only", bundle.path,
            "--version", "9.9.9", "--build", "4242",
        ]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
        } catch {
            XCTFail("could not run \(script.path): \(error)")
            throw PackagedPlistFixtureError.unavailable
        }
        // The pipe is read before the wait, never after it: a child that
        // writes more than the pipe holds blocks on its own write, and the
        // wait for it would never come back.
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            XCTFail("package-mac.sh --plist-only failed (\(process.terminationStatus)): \(text)")
            throw PackagedPlistFixtureError.unavailable
        }
        return bundle.appendingPathComponent("Contents/Info.plist")
    }

    /// Walk up from this source file to the checkout that holds the scripts.
    private func repositoryRoot() -> URL? {
        var url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<12 {
            let script = url.appendingPathComponent("scripts/package-mac.sh")
            if FileManager.default.isExecutableFile(atPath: script.path) {
                return url
            }
            let parent = url.deletingLastPathComponent()
            if parent.path == url.path {
                return nil
            }
            url = parent
        }
        return nil
    }
}
