// The one gate in front of the menu's proposal actions (Send proposal, Edit
// proposal, Not now): no menu action touches a Waiting card that a sheet, an
// alert or a modal covers. AppKit's state comes in as a value, so no window is
// ever opened here.
import Foundation
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class ProposalMenuGateTests: XCTestCase {
    /// Waiting for you, Camille's ask selected and on screen.
    private func waitingShell() -> (shell: ShellModel, ask: Approval)? {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        guard waitUntil({ shell.store.approvals.count == 2 }),
              let ask = shell.store.approvals.first(where: { $0.id == "ap-camille" }) else { return nil }
        shell.go(.waiting)
        shell.store.focus(ask.id)
        return (shell, ask)
    }

    private var covers: [(name: String, cover: MainWindowCover)] {
        [
            ("no window on screen", MainWindowCover(noWindowOnScreen: true)),
            ("a sheet on a window", MainWindowCover(sheetAttached: true)),
            ("a sheet as the key window", MainWindowCover(keyWindowIsSheet: true)),
            ("an app-modal panel", MainWindowCover(modalSession: true)),
        ]
    }

    private func assertNothingChanged(_ shell: ShellModel, _ ask: Approval, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(shell.countdowns.isEmpty, "nothing was sent", file: file, line: line)
        XCTAssertFalse(shell.snoozed.contains(ask.id), "nothing was set aside", file: file, line: line)
        XCTAssertNil(shell.editing, "no editor opened", file: file, line: line)
    }

    func testWithNothingOverTheWindowEveryActionReachesTheCardOnScreen() {
        guard let (shell, ask) = waitingShell() else { return XCTFail("fixture approval") }
        XCTAssertFalse(MainWindowCover.clear.coversWindow)
        for action in ProposalMenuGate.Action.allCases {
            XCTAssertEqual(ProposalMenuGate.target(for: action, in: shell, cover: .clear, textFieldFocused: false)?.id, ask.id, "\(action)")
        }
    }

    func testAnySheetAlertOrModalTheModelNeverSeesKeepsEveryActionOff() {
        guard let (shell, ask) = waitingShell() else { return XCTFail("fixture approval") }
        // A view's own sheet (the sidebar mascot, Clients import, an alert):
        // the model still selects the card; only AppKit knows it is covered.
        XCTAssertEqual(shell.selectedWaitingApproval?.id, ask.id)
        for (name, cover) in covers {
            XCTAssertTrue(cover.coversWindow, name)
            for action in ProposalMenuGate.Action.allCases {
                XCTAssertNil(ProposalMenuGate.target(for: action, in: shell, cover: cover, textFieldFocused: false), "\(action) drawn under \(name)")
                XCTAssertFalse(ProposalMenuGate.perform(action, in: shell, cover: cover, textFieldFocused: false), "\(action) run under \(name)")
            }
        }
        assertNothingChanged(shell, ask)
    }

    func testEverySheetTheModelOpensKeepsEveryActionOff() {
        guard let (shell, ask) = waitingShell() else { return XCTFail("fixture approval") }
        XCTAssertFalse(shell.sheetPresented)
        let sheets: [(name: String, open: (ShellModel) -> Void, close: (ShellModel) -> Void)] = [
            ("Settings", { $0.settingsTab = ShellModel.SettingsTab.allCases.first }, { $0.settingsTab = nil }),
            ("Add an Agent", { $0.beginAddAgent() }, { $0.addingAgent = nil }),
            ("Keyboard Shortcuts", { $0.shortcutHelpOpen = true }, { $0.shortcutHelpOpen = false }),
            ("Setup", { $0.setupOpen = true }, { $0.setupOpen = false }),
        ]
        for sheet in sheets {
            sheet.open(shell)
            XCTAssertTrue(shell.sheetPresented, sheet.name)
            XCTAssertNil(shell.selectedWaitingApproval, "\(sheet.name) covers the card")
            for action in ProposalMenuGate.Action.allCases {
                XCTAssertFalse(ProposalMenuGate.perform(action, in: shell, cover: .clear, textFieldFocused: false), "\(action) under \(sheet.name)")
            }
            sheet.close(shell)
            XCTAssertFalse(shell.sheetPresented, sheet.name)
        }
        XCTAssertEqual(shell.selectedWaitingApproval?.id, ask.id, "with every sheet closed the card is on screen again")
        assertNothingChanged(shell, ask)
    }

    func testTheGateRunsEachActionOnTheCardOnScreen() {
        guard let (shell, ask) = waitingShell() else { return XCTFail("fixture approval") }
        // A text field with the keyboard keeps Edit and Not now off, as before.
        XCTAssertFalse(ProposalMenuGate.perform(.edit, in: shell, cover: .clear, textFieldFocused: true))
        XCTAssertFalse(ProposalMenuGate.perform(.notNow, in: shell, cover: .clear, textFieldFocused: true))
        assertNothingChanged(shell, ask)

        XCTAssertTrue(ProposalMenuGate.perform(.edit, in: shell, cover: .clear, textFieldFocused: false))
        XCTAssertEqual(shell.editing, ask.id)
        XCTAssertNil(ProposalMenuGate.target(for: .edit, in: shell, cover: .clear, textFieldFocused: false), "already editing")
        // ⌘Return in the open editor (a text view has the keyboard) sends the edit.
        XCTAssertTrue(ProposalMenuGate.perform(.send, in: shell, cover: .clear, textFieldFocused: true))
        XCTAssertNotNil(shell.countdowns[ask.id], "the yes waits behind its Undo")
        XCTAssertNil(ProposalMenuGate.target(for: .send, in: shell, cover: .clear, textFieldFocused: false), "a counting card is not sent twice")

        shell.undo(ask)
        XCTAssertTrue(ProposalMenuGate.perform(.notNow, in: shell, cover: .clear, textFieldFocused: false))
        XCTAssertTrue(shell.snoozed.contains(ask.id))
    }

    /// Now and in future code: a `Commands` body never calls an approval action
    /// itself, so every menu path to one goes through `ProposalMenuGate`.
    func testNoMenuCommandActsOnAnApprovalAroundTheGate() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AuxesisMac", isDirectory: true)
        guard let enumerator = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil) else {
            return XCTFail("could not scan \(sources.path)")
        }
        var bodies = 0
        var bypasses: [String] = []
        while let file = enumerator.nextObject() as? URL {
            guard file.pathExtension == "swift" else { continue }
            let source = try String(contentsOf: file, encoding: .utf8)
            let commands = Self.commandsBodies(in: source)
            bodies += commands.count
            bypasses += commands.flatMap(Self.approvalCalls).map { "\(file.lastPathComponent): \($0)" }
        }
        XCTAssertGreaterThanOrEqual(bodies, 2, "TeamCommands and UpdateCommands were not found")
        XCTAssertTrue(bypasses.isEmpty, "menu code acts on an approval without ProposalMenuGate:\n\(bypasses.joined(separator: "\n"))")
    }

    func testTheMenuScanCatchesADirectCall() {
        let menu = """
        struct LateCommands: Equatable, Commands {
            var body: some Commands {
                CommandMenu("Agents") {
                    Button("Send") { if let selected { shell.sendProposal(selected) } }
                    Button("Not now") { runProposal(.notNow) }.menuShortcut(.notNow)
                }
            }
        }
        struct Elsewhere { func f() { shell.approve(a) } }
        """
        let bodies = Self.commandsBodies(in: menu)
        XCTAssertEqual(bodies.count, 1, "only the Commands body is scanned")
        XCTAssertEqual(bodies.flatMap(Self.approvalCalls), ["Button(\"Send\") { if let selected { shell.sendProposal(selected) } }"])
    }

    /// Each `struct …: Commands { … }` body, braces matched.
    private nonisolated static func commandsBodies(in source: String) -> [String] {
        var bodies: [String] = []
        var rest = source[...]
        while let head = rest.range(of: #"struct\s+\w+\s*:[^{]*\bCommands\b[^{]*\{"#, options: .regularExpression) {
            var depth = 1
            var end = head.upperBound
            while end < rest.endIndex, depth > 0 {
                if rest[end] == "{" { depth += 1 } else if rest[end] == "}" { depth -= 1 }
                end = rest.index(after: end)
            }
            bodies.append(String(rest[head.upperBound..<end]))
            rest = rest[end...]
        }
        return bodies
    }

    /// Lines that call an action which sends, approves, edits or dismisses an approval.
    private nonisolated static func approvalCalls(in body: String) -> [String] {
        let actions = ["sendProposal", "sendEdited", "approve", "undo", "notNow", "beginEdit", "cancelEdit", "reopen", "resolve", "deny"]
        return body.components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { line in actions.contains { line.contains(".\($0)(") } }
    }
}
