// The mascot sheet: Done saves the pick, Cancel leaves the saved
// look alone, Reset gives the default, the same-look line shows only when
// another agent wears the same mascot and tint, the arrows walk the 5 × 2
// grid, and no agent, mascot or tint name is a brand name.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class MascotPickerTests: XCTestCase {
    private func withLooks(_ suite: String, _ body: (AgentLooks) -> Void) {
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        defer { defaults.removePersistentDomain(forName: suite) }
        body(AgentLooks(defaults: defaults))
    }

    func testPickingThenDoneSaves() {
        withLooks("auxesis.mascot.tests.picker-done") { looks in
            var picker = MascotPicker(agentId: "mail", looks: looks)
            XCTAssertEqual(picker.look, MascotLook(.glance), "the sheet opens on the saved look")
            picker.look.variant = .visor
            picker.look.tint = .plum
            XCTAssertEqual(looks.look(for: "mail"), MascotLook(.glance), "nothing is saved before Done")
            picker.save(to: looks)
            XCTAssertEqual(looks.look(for: "mail"), MascotLook(.visor, .plum), "Done saves the pick")
            XCTAssertEqual(MascotPicker(agentId: "mail", looks: looks).look, MascotLook(.visor, .plum), "and the sheet reopens on it")
        }
    }

    func testCancelKeepsTheSavedLook() {
        withLooks("auxesis.mascot.tests.picker-cancel") { looks in
            looks.set(MascotLook(.calm, .bark), for: "calendar")
            // The sheet opens on the saved look.
            var picker = MascotPicker(agentId: "calendar", looks: looks)
            XCTAssertEqual(picker.look, MascotLook(.calm, .bark), "the sheet opens on the saved look")
            // The owner picks another mascot and another tint in the sheet.
            picker.look.variant = .wide
            picker.look.tint = .slate
            XCTAssertEqual(picker.look, MascotLook(.wide, .slate), "the sheet holds the pick")
            XCTAssertEqual(looks.look(for: "calendar"), MascotLook(.calm, .bark), "nothing is saved before Done")
            // The sheet's Cancel button calls exactly this.
            picker.cancel(looks)
            XCTAssertEqual(looks.look(for: "calendar"), MascotLook(.calm, .bark), "Cancel keeps the saved look")
            XCTAssertEqual(picker.look, MascotLook(.calm, .bark), "and drops the pick")
        }
    }

    /// The sheet's own source: the Cancel button must take the model's cancel
    /// path and never the save path. The test above proves the rule; this
    /// proves the button takes that path.
    func testTheSheetCancelButtonTakesTheModelsCancelPath() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let file = packageRoot.appendingPathComponent("Sources/AuxesisMac/MascotPickerSheet.swift")
        let source = try String(contentsOf: file, encoding: .utf8)
        guard let identifier = source.range(of: "accessibilityIdentifier(\"mascot-cancel\")") else {
            XCTFail("the sheet's Cancel button was not found")
            return
        }
        let before = source[source.startIndex..<identifier.lowerBound]
        guard let button = before.range(of: "Button {", options: .backwards) else {
            XCTFail("the sheet's Cancel button has no action of its own")
            return
        }
        let action = String(source[button.upperBound..<identifier.lowerBound])
        XCTAssertTrue(action.contains("cancel(looks)"), "the Cancel button calls the model's cancel: \(action)")
        XCTAssertFalse(action.contains("save(to:"), "the Cancel button never saves: \(action)")
    }

    func testResetGivesTheDefault() {
        withLooks("auxesis.mascot.tests.picker-reset") { looks in
            looks.set(MascotLook(.tall, .graphite), for: "documents")
            var picker = MascotPicker(agentId: "documents", looks: looks)
            XCTAssertFalse(picker.isDefault, "Reset is live when the look is not the default")
            picker.reset()
            XCTAssertTrue(picker.isDefault, "Reset dims once the look is the default")
            XCTAssertEqual(picker.look, MascotLook(.specs, .ink))
            picker.save(to: looks)
            XCTAssertEqual(looks.look(for: "documents"), MascotLook(.specs, .ink))
            var travel = MascotPicker(agentId: "travel", looks: looks)
            travel.look = MascotLook(.hook, .plum)
            travel.reset()
            XCTAssertEqual(travel.look, MascotLook(.sprout, .ink), "an agent the owner made resets to Sprout")
        }
    }

    func testTheSameLookLineShowsOnlyWhenAnotherAgentLooksTheSame() {
        withLooks("auxesis.mascot.tests.picker-twin") { looks in
            let team = TeamMember.all.map(\.id) + ["travel"]
            var picker = MascotPicker(agentId: "travel", looks: looks)
            XCTAssertNil(picker.twin(among: team, looks: looks), "Sprout in Ink is no one else's look")
            picker.look = MascotLook(.specs)
            XCTAssertEqual(picker.twin(among: team, looks: looks), "documents", "Documents looks the same")
            picker.look.tint = .slate
            XCTAssertNil(picker.twin(among: team, looks: looks), "a different tint tells them apart")
            looks.set(MascotLook(.specs, .slate), for: "clients")
            XCTAssertEqual(picker.twin(among: team, looks: looks), "clients", "compared with the saved looks")
            let mail = MascotPicker(agentId: "mail", looks: looks)
            XCTAssertNil(mail.twin(among: team, looks: looks), "an agent never matches itself")
        }
    }

    func testTheArrowsWalkTheGridAndTheEdgesHold() {
        XCTAssertEqual(MascotPicker.move(.loop, dx: 1, dy: 0), .glance)
        XCTAssertEqual(MascotPicker.move(.loop, dx: -1, dy: 0), .loop, "the left edge holds")
        XCTAssertEqual(MascotPicker.move(.loop, dx: 0, dy: -1), .loop, "the top edge holds")
        XCTAssertEqual(MascotPicker.move(.specs, dx: 0, dy: 1), .sprout, "down one row")
        XCTAssertEqual(MascotPicker.move(.calm, dx: 1, dy: 0), .calm, "the right edge holds, no wrap")
        XCTAssertEqual(MascotPicker.move(.hook, dx: 0, dy: 1), .hook, "the bottom edge holds")
        XCTAssertEqual(MascotPicker.move(.twin, dx: 0, dy: -1), .visor)
    }

    func testASaveTellsEveryMascotOnScreen() {
        withLooks("auxesis.mascot.tests.picker-notice") { looks in
            var told: [String] = []
            let token = NotificationCenter.default.addObserver(forName: AgentLooks.didChange, object: nil, queue: nil) {
                told.append($0.object as? String ?? "")
            }
            defer { NotificationCenter.default.removeObserver(token) }
            looks.set(MascotLook(.wide), for: "mail")
            looks.reset("mail")
            XCTAssertEqual(told, ["mail", "mail"], "a save and a reset both redraw the agent's mascots")
        }
    }

    // The brand guard: the names of the old brand sheet are the
    // brand's, not the app's. No agent, mascot, tint or copy string says one.
    func testNoBrandNameReachesAUserVisibleString() {
        var lines: [(String, String)] = []
        for member in TeamMember.all { lines.append(("agent.\(member.id)", member.name)) }
        for variant in MascotVariant.allCases { lines.append(("mascot.\(variant.rawValue)", variant.name)) }
        for tint in MascotTint.allCases { lines.append(("tint.\(tint.rawValue)", tint.name)) }
        for (key, values) in L10n.uiTable {
            for (language, text) in values { lines.append(("\(key.rawValue).\(language.rawValue)", text)) }
        }
        for (key, values) in L10n.table {
            for (language, text) in values { lines.append(("\(key.rawValue).\(language.rawValue)", text)) }
        }
        XCTAssertGreaterThan(lines.count, 100, "the copy tables are read")
        for (key, text) in lines {
            for name in BrandGuard.names {
                XCTAssertFalse(BrandGuard.says(text, name), "\(key) says the brand name \(name)")
            }
        }
    }
}
