import AppKit
import SwiftUI
import Testing
@testable import AuxesisKit
@testable import AuxesisMac

/// Opening "Since you left" from the Records menu killed
/// the app with AppKit's "more Update Constraints in Window passes than there
/// are views in the window". The detail column's height followed its width,
/// and in the v5 frame that width is what the window leaves beside the list,
/// so each layout pass asked for another. Every Records page is opened here the
/// way the owner opens it, in the v5 frame at its smallest window, and laid out
/// for several passes: a loop raises that exception and kills this test run.
@objcMembers @MainActor final class RecordPageLayoutTests: XCTestCase {
    func testEveryRecordsPageLaysOutInTheV5FrameWithoutALoop() {
        // A fixture run, as the app's sandboxed snapshots are: no first-run Setup sheet.
        let saved = ["AUXESIS_SANDBOX", "AUXESIS_MAC_FIXTURE"].map { name in (name, ProcessInfo.processInfo.environment[name]) }
        setenv("AUXESIS_SANDBOX", "1", 1)
        setenv("AUXESIS_MAC_FIXTURE", FixtureDaemon.Scenario.team.rawValue, 1)
        defer { for (name, value) in saved { if let value { setenv(name, value, 1) } else { unsetenv(name) } } }
        XCTAssertEqual(AppEnvironment.fixture, .team)

        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.memoryPage = MemoryPageModel(client: daemon)
        shell.start()
        shell.loadLedger()
        XCTAssertTrue(waitUntil { !(shell.ledger.value ?? []).isEmpty }, "the fixture ledger never loaded")

        let host = NSHostingView(rootView: ShellView().environmentObject(shell).themed())
        // The app's smallest window (ShellView's minimum), never shown: alpha 0, never ordered in.
        let window = NSWindow(contentRect: CGRect(x: 0, y: 0, width: 1100, height: 700),
                              styleMask: [.titled, .closable, .resizable, .miniaturizable, .fullSizeContentView],
                              backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.alphaValue = 0
        window.contentView = host
        defer { window.contentView = nil; window.close() }

        for route in ShellModel.recordsMenu.flatMap({ $0 }) {
            shell.go(.agent(TeamMember.aux.id))
            settle(window)
            shell.go(route)
            settle(window)
            XCTAssertEqual(shell.route, route)
        }
        // The page that looped: its first entry is selected and its detail drawn.
        shell.go(.sinceYouLeft)
        settle(window)
        XCTAssertNotNil((shell.ledger.value ?? []).first)
    }

    /// Several layout passes with the run loop drained between them, as the
    /// window's display cycle does.
    private func settle(_ window: NSWindow) {
        for _ in 0..<6 {
            _ = waitUntil(timeout: 0.05) { false }
            window.contentView?.needsLayout = true
            window.layoutIfNeeded()
            window.contentView?.layoutSubtreeIfNeeded()
        }
    }
}
