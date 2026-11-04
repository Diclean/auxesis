// Agent mascots: each agent's default look, the owner's pick
// kept across launches in a file-backed UserDefaults suite, a broken value
// falling back, and tints that never borrow a meaning hue.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class MascotTests: XCTestCase {
    private func withLooks(_ suite: String, _ body: (UserDefaults, AgentLooks) -> Void) {
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        defer { defaults.removePersistentDomain(forName: suite) }
        body(defaults, AgentLooks(defaults: defaults))
    }

    func testEachBuiltInAgentHasItsDefaultMascotInInk() {
        let expected: [String: MascotVariant] = [
            "aux": .loop, "mail": .glance, "calendar": .hook, "clients": .twin, "documents": .specs,
        ]
        XCTAssertEqual(Set(expected.keys), Set(TeamMember.all.map(\.id)), "every built-in agent has a default")
        withLooks("auxesis.mascot.tests.defaults") { _, looks in
            for (agent, variant) in expected {
                XCTAssertEqual(looks.look(for: agent), MascotLook(variant, .ink), "the default look of \(agent)")
            }
        }
    }

    func testAnAgentTheOwnerAddedStartsAsSprout() {
        withLooks("auxesis.mascot.tests.sprout") { _, looks in
            for agent in ["travel", "researcher", "Mail", ""] {
                XCTAssertEqual(looks.look(for: agent), MascotLook(.sprout, .ink), "\(agent) is new")
            }
        }
    }

    func testAPickSurvivesARelaunch() {
        let suite = "auxesis.mascot.tests.roundtrip"
        withLooks(suite) { defaults, looks in
            looks.set(MascotLook(.visor, .plum), for: "mail")
            XCTAssertEqual(defaults.string(forKey: "agentLook.mail"), "visor:plum", "stored as mascot:tint")
            // A new store over the same suite is the app after a relaunch.
            XCTAssertEqual(AgentLooks(defaults: UserDefaults(suiteName: suite)!).look(for: "mail"), MascotLook(.visor, .plum))
            XCTAssertEqual(looks.look(for: "calendar"), MascotLook(.hook), "one agent's pick leaves the others alone")
            looks.set(MascotLook(.glance), for: "mail")
            XCTAssertNil(defaults.string(forKey: "agentLook.mail"), "picking the default clears the key")
            looks.set(MascotLook(.tall, .bark), for: "documents")
            looks.reset("documents")
            XCTAssertEqual(looks.look(for: "documents"), MascotLook(.specs), "reset brings the default back")
        }
    }

    func testEveryLookRoundTripsThroughItsStoredForm() {
        for variant in MascotVariant.allCases {
            for tint in MascotTint.allCases {
                let look = MascotLook(variant, tint)
                XCTAssertEqual(MascotLook(stored: look.stored), look)
            }
        }
        XCTAssertEqual(MascotVariant.allCases.count, 10)
        XCTAssertEqual(MascotTint.allCases.count, 5)
    }

    func testABrokenStoredValueFallsBackToTheDefault() {
        withLooks("auxesis.mascot.tests.broken") { defaults, looks in
            for bad in ["", "glance", "glance:", "unicorn:ink", "glance:amber", "glance:slate:x", "GLANCE:SLATE"] {
                defaults.set(bad, forKey: "agentLook.clients")
                XCTAssertEqual(looks.look(for: "clients"), MascotLook(.twin), "\"\(bad)\" falls back")
            }
            defaults.set(42, forKey: "agentLook.clients")
            XCTAssertEqual(looks.look(for: "clients"), MascotLook(.twin), "a non-string falls back")
        }
    }

    /// No tint is a meaning hue (amber, green, red, indigo), each stays
    /// low-chroma, and each reads at least 3:1 on the view it sits on.
    func testTintsNeverBorrowAMeaningHue() {
        for tint in MascotTint.allCases {
            for (value, palette) in [(tint.light, Palette.light), (tint.dark, Palette.dark)] {
                let meaning = [palette.amber, palette.green, palette.red, palette.out]
                XCTAssertFalse(meaning.contains { $0.hexString == value.hexString }, "\(tint.name) is not a meaning hue")
                let channels = [value.red, value.green, value.blue]
                XCTAssertLessThan(channels.max()! - channels.min()!, 0.25, "\(tint.name) \(value.hexString) is low-chroma")
                XCTAssertGreaterThanOrEqual(Contrast.ratio(value, palette.work), 3, "\(tint.name) \(value.hexString) reads on its view")
                XCTAssertGreaterThanOrEqual(Contrast.ratio(value, palette.list), 3, "\(tint.name) \(value.hexString) reads in the sidebar")
            }
        }
        XCTAssertNotEqual(MascotLook.clay.hexString, Palette.light.amber.hexString, "the clay dot is not the wait hue")
    }

    func testHandoffPiecesPutAMascotBeforeEachName() {
        let line = HandoffLine.text(agents: ["mail", "calendar"], at: nil, language: .en)
        let pieces = HandoffLine.pieces(line, agents: ["aux", "mail", "calendar"])
        XCTAssertEqual(pieces.map(\.agent), ["aux", "mail", "calendar"])
        XCTAssertEqual(pieces.map(\.text).joined(), line, "the pieces join back to the line")
        XCTAssertTrue(pieces[1].text.hasPrefix("Mail"))
        let missing = HandoffLine.pieces("Aux asked Mail", agents: ["aux", "travel"])
        XCTAssertEqual(missing.map(\.agent), ["aux"], "a name the line does not carry gets no mascot")
        XCTAssertEqual(missing.map(\.text).joined(), "Aux asked Mail")
    }

    // The guard the SVG badges had, ported to the
    // mascots. The names of the old brand sheet are the brand's, not the
    // app's: no mascot, no tint and no source file that draws a mascot says
    // one. The scan walks every source file, not a hand-kept list, so a new
    // file is covered the day it lands. (The copy tables are guarded in
    // MascotPickerTests; the names and the word check live in BrandGuard.)
    func testNoMascotSourceSaysABrandName() throws {
        let sources = try BrandGuard.sources()
        XCTAssertGreaterThan(sources.count, 10, "the brand guard scanned the app's sources")
        for file in sources {
            for brand in BrandGuard.names {
                XCTAssertFalse(BrandGuard.says(file.source, brand), "\(file.path) says the brand name \(brand)")
            }
        }
    }
}
