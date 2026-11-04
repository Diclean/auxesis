// A golden file locks every effective user-visible string
// in both languages, so any copy change shows up in review as a fixture diff.
//
// Regenerate only on purpose, then review and commit the fixture diff:
//   cd apps/auxesis-mac
//   AUXESIS_UPDATE_COPY_SNAPSHOT=1 swift test --filter CopySnapshotTests
// The update run always fails with "fixture updated, review the diff"; it
// never regenerates silently and never rewrites the file on a normal run.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class CopySnapshotTests: XCTestCase {
    private struct Snapshot: Codable {
        let ui: [String: [String: String]]
        let string: [String: [String: String]]
        let uiMissingFrench: [String]
    }

    private static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/CopySnapshot.json")
    }

    /// The effective copy: `L10n.ui` falls back to EN, `L10n.t` is exact.
    private static func liveSnapshot() -> Snapshot {
        var ui: [String: [String: String]] = [:]
        var string: [String: [String: String]] = [:]
        var missingFrench: [String] = []
        var uiNames = Set<String>()
        for key in UIKey.allCases {
            XCTAssertTrue(uiNames.insert(key.rawValue).inserted, "duplicate UIKey name: \(key.rawValue)")
            ui[key.rawValue] = ["en": L10n.ui(key, .en), "fr": L10n.ui(key, .fr)]
            if (L10n.uiTable[key]?[.fr] ?? "").isEmpty { missingFrench.append(key.rawValue) }
        }
        var stringNames = Set<String>()
        for key in StringKey.allCases {
            XCTAssertTrue(stringNames.insert(key.rawValue).inserted, "duplicate StringKey name: \(key.rawValue)")
            string[key.rawValue] = ["en": L10n.t(key, .en), "fr": L10n.t(key, .fr)]
        }
        return Snapshot(ui: ui, string: string, uiMissingFrench: missingFrench.sorted())
    }

    func testEveryEffectiveUserVisibleStringMatchesTheSnapshot() throws {
        let live = Self.liveSnapshot()

        if ProcessInfo.processInfo.environment["AUXESIS_UPDATE_COPY_SNAPSHOT"] == "1" {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            try encoder.encode(live).write(to: Self.fixtureURL, options: .atomic)
            XCTFail("fixture updated, review the diff")
            return
        }

        let golden = try JSONDecoder().decode(Snapshot.self, from: Data(contentsOf: Self.fixtureURL))
        var problems = Self.compare("ui", golden.ui, live.ui)
        problems += Self.compare("string", golden.string, live.string)
        for key in Set(golden.uiMissingFrench).symmetricDifference(live.uiMissingFrench).sorted() {
            problems.append("uiMissingFrench.\(key) expected \(golden.uiMissingFrench.contains(key)) "
                + "actual \(live.uiMissingFrench.contains(key))")
        }
        for problem in problems { print("CopySnapshot: \(problem)") }
        if !problems.isEmpty {
            XCTFail("\(problems.count) copy snapshot difference(s); "
                + "each one printed its key, language, expected and actual")
        }
    }

    private static func compare(
        _ table: String,
        _ expected: [String: [String: String]],
        _ actual: [String: [String: String]]
    ) -> [String] {
        var problems: [String] = []
        for key in Set(expected.keys).union(actual.keys).sorted() {
            let want = expected[key]
            let got = actual[key]
            for language in ["en", "fr"] where want?[language] != got?[language] {
                problems.append("\(table).\(key) [\(language)] "
                    + "expected \(quoted(want?[language])) actual \(quoted(got?[language]))")
            }
        }
        return problems
    }

    private static func quoted(_ value: String?) -> String {
        value.map { "\"\($0)\"" } ?? "<missing>"
    }
}
